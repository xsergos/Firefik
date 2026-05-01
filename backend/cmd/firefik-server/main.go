package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"firefik/internal/controlplane"
	pb "firefik/internal/controlplane/gen/controlplanev1"
	"firefik/internal/controlplane/mca"
	"firefik/internal/telemetry"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "mini-ca":
			if err := runMiniCA(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "firefik-server mini-ca:", err)
				os.Exit(1)
			}
			return
		case "backup":
			if err := runBackup(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "firefik-server backup:", err)
				os.Exit(1)
			}
			return
		case "restore":
			if err := runRestore(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "firefik-server restore:", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "firefik-server:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8443", "bind address for the HTTP enroll / healthz endpoints")
	grpcListen := flag.String("grpc-listen", ":8444", "bind address for the gRPC transport (empty disables)")
	certFile := flag.String("cert", "", "TLS certificate (PEM)")
	keyFile := flag.String("key", "", "TLS key (PEM)")
	clientCA := flag.String("client-ca", "", "client CA bundle (PEM); enables mTLS when set")
	caStateDir := flag.String("ca-state-dir", defaultCAStateDir(), "embedded mini-CA state dir (empty disables /v1/enroll)")
	trustDomain := flag.String("trust-domain", trustDomainFromEnv(), "SPIFFE trust domain (enables SAN verification when set)")
	tokenFile := flag.String("token-file", "", "shared bearer token file for agent auth")
	dbPath := flag.String("db", defaultDBPath(), "sqlite path; empty or ':memory:' means in-memory")
	commandTTL := flag.Duration("command-ttl", 24*time.Hour, "pending commands older than this are expired")
	auditRetention := flag.Duration("audit-retention", 90*24*time.Hour, "audit rows older than this are purged")
	snapshotsPerAgent := flag.Int("snapshots-per-agent", 100, "max retained snapshot rows per agent")
	retentionInterval := flag.Duration("retention-interval", 15*time.Minute, "how often the retention loop runs")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	logsCtx, logsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	logsShutdown, err := telemetry.InitLogs(logsCtx, "firefik-server", logger)
	logsCancel()
	if err != nil {
		logger.Warn("opentelemetry logs init failed", "error", err)
	} else {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := logsShutdown(shutdownCtx); err != nil {
				logger.Warn("opentelemetry logs shutdown failed", "error", err)
			}
		}()
	}

	token := ""
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read token-file: %w", err)
		}
		token = string(b)
	} else if v := os.Getenv("FIREFIK_SERVER_TOKEN"); v != "" {
		token = v
	}

	var ca *mca.CA
	if *caStateDir != "" {
		if _, err := os.Stat(*caStateDir); err == nil {
			c, err := mca.Open(*caStateDir, *trustDomain)
			if err != nil {
				logger.Warn("mini-CA open failed; /v1/enroll disabled", "error", err)
			} else {
				ca = c
			}
		}
	}

	ctxBoot, bootCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer bootCancel()
	var store controlplane.Store
	if *dbPath != "" {
		s, err := controlplane.NewSQLiteStore(ctxBoot, *dbPath, logger)
		if err != nil {
			return fmt.Errorf("init store: %w", err)
		}
		store = s
		defer func() { _ = store.Close() }()
	} else {
		store = controlplane.NewMemoryStore()
	}
	registry := controlplane.NewRegistryWithStore(logger, store)

	var enrollHandler controlplane.EnrollHandler
	if ca != nil {
		enrollHandler = makeEnrollHandler(ca, token, logger)
	}

	auditFanOut := buildServerAudit(logger)
	defer func() {
		for _, sink := range auditFanOut.Sinks {
			_ = sink.Close()
		}
	}()

	srv := &controlplane.HTTPServer{
		EnrollHandle: enrollHandler,
		Registry:     registry,
		Token:        token,
		Audit:        auditFanOut,
	}

	httpSrv := &http.Server{
		Addr:         *listen,
		Handler:      srv.Handler(),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	tlsCfg, err := buildTLS(*certFile, *keyFile, *clientCA, *trustDomain)
	if err != nil {
		return err
	}
	httpSrv.TLSConfig = tlsCfg

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	retentionCtx, retentionCancel := context.WithCancel(ctx)
	defer retentionCancel()
	go func() {
		_ = registry.RunRetentionLoop(retentionCtx, *retentionInterval, *commandTTL, *auditRetention, *snapshotsPerAgent)
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listen, err)
	}
	logger.Info("firefik-server ready",
		"http_addr", *listen,
		"grpc_addr", *grpcListen,
		"tls", tlsCfg != nil,
		"mtls", *clientCA != "",
		"trust_domain", *trustDomain,
		"enroll", ca != nil,
		"token_required", token != "",
		"db", *dbPath,
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if tlsCfg != nil {
			if err := httpSrv.ServeTLS(ln, *certFile, *keyFile); err != nil && err != http.ErrServerClosed {
				return err
			}
		} else {
			if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				return err
			}
		}
		return nil
	})

	if *grpcListen != "" {
		gln, err := net.Listen("tcp", *grpcListen)
		if err != nil {
			return fmt.Errorf("listen %s: %w", *grpcListen, err)
		}

		var serverOpts []grpc.ServerOption
		if tlsCfg != nil {
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		}
		if token != "" {
			serverOpts = append(serverOpts,
				grpc.UnaryInterceptor(unaryAuth(token)),
				grpc.StreamInterceptor(streamAuth(token)),
			)
		}
		gs := grpc.NewServer(serverOpts...)
		grpcSvc := &controlplane.GRPCServer{
			Registry: registry,
			Token:    token,
			Logger:   logger,
		}
		pb.RegisterControlPlaneServer(gs, grpcSvc)

		g.Go(func() error {
			if err := gs.Serve(gln); err != nil && err != grpc.ErrServerStopped {
				return fmt.Errorf("grpc serve: %w", err)
			}
			return nil
		})
		g.Go(func() error {
			<-gctx.Done()
			gs.GracefulStop()
			return nil
		})
	}

	return g.Wait()
}

func unaryAuth(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkBearer(ctx, token); err != nil {
			return nil, err
		}
		return handler(controlplane.WithBearer(ctx, token), req)
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context { return w.ctx }

func streamAuth(token string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkBearer(ss.Context(), token); err != nil {
			return err
		}
		return handler(srv, &wrappedServerStream{ServerStream: ss, ctx: controlplane.WithBearer(ss.Context(), token)})
	}
}

func checkBearer(ctx context.Context, expected string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no metadata")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "authorization missing")
	}
	if values[0] != "Bearer "+expected {
		return status.Error(codes.Unauthenticated, "invalid bearer token")
	}
	return nil
}

func defaultDBPath() string {
	if v := os.Getenv("FIREFIK_CP_DB"); v != "" {
		return v
	}
	return "/var/lib/firefik-server/firefik.db"
}

func trustDomainFromEnv() string {
	if v := os.Getenv("FIREFIK_CP_TRUST_DOMAIN"); v != "" {
		return v
	}
	return ""
}

func buildTLS(cert, key, clientCA, trustDomain string) (*tls.Config, error) {
	if cert == "" && key == "" && clientCA == "" {
		return nil, nil
	}
	if cert == "" || key == "" {
		return nil, fmt.Errorf("--cert and --key are both required")
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if clientCA != "" {
		caPEM, err := os.ReadFile(clientCA)
		if err != nil {
			return nil, fmt.Errorf("read client-ca: %w", err)
		}
		pool, err := readCertPool(caPEM)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if trustDomain != "" {
		base := mca.VerifySPIFFEPeer(trustDomain)
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if err := base(rawCerts, chains); err != nil {
				reason := "no_spiffe_san"
				if len(rawCerts) == 0 {
					reason = "no_peer_cert"
				}
				controlplane.IncMTLSRejected(reason)
				return err
			}
			return nil
		}
	}
	return cfg, nil
}

func makeEnrollHandler(ca *mca.CA, token string, logger *slog.Logger) controlplane.EnrollHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req controlplane.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			http.Error(w, "agent_id required", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		result, err := ca.Issue(mca.IssueRequest{AgentID: req.AgentID, TTL: ttl})
		if err != nil {
			logger.Warn("enroll issue failed", "error", err)
			http.Error(w, "issue failed", http.StatusInternalServerError)
			return
		}
		resp := controlplane.EnrollResponse{
			CertPEM:      string(result.CertPEM),
			KeyPEM:       string(result.KeyPEM),
			BundlePEM:    string(result.BundlePEM),
			Serial:       result.SerialHex,
			SPIFFEURI:    result.SPIFFEURI,
			NotAfterUnix: result.NotAfter.Unix(),
		}
		controlplane.IncCACertsIssued()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		logger.Info("agent certificate issued", "agent_id", req.AgentID, "serial", result.SerialHex)
	}
}
