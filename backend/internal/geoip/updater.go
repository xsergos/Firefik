package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

const (
	SourceP3TERX  = "p3terx"
	SourceMaxmind = "maxmind"
	SourceURL     = "url"
)

const (
	p3terxDownloadURL  = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"
	maxmindDownloadURL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz"
	downloadTimeout    = 5 * time.Minute
	maxRedirects       = 5
)

type SourceConfig struct {
	Source      string
	LicenseKey  string
	DownloadURL string
	Version     string
}

type Updater struct {
	dbPath   string
	source   SourceConfig
	cronExpr string
	logger   *slog.Logger
	onUpdate func(newDB *DB)
	client   *http.Client

	mu   sync.Mutex
	cron *cron.Cron
}

func NewUpdater(dbPath string, source SourceConfig, cronExpr string, logger *slog.Logger, onUpdate func(newDB *DB)) *Updater {
	return &Updater{
		dbPath:   dbPath,
		source:   source,
		cronExpr: cronExpr,
		logger:   logger,
		onUpdate: onUpdate,
		client:   newHTTPClient(),
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: downloadTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

func (u *Updater) Run(ctx context.Context) error {
	if err := u.validate(); err != nil {
		u.logger.Warn("GeoIP auto-update disabled", "error", err)
		return nil
	}

	if err := u.downloadIfMissing(); err != nil {
		u.logger.Warn("initial GeoIP download failed", "error", err)
	}

	u.cron = cron.New()
	_, err := u.cron.AddFunc(u.cronExpr, func() {
		u.logger.Info("GeoIP scheduled update starting")
		changed, err := u.download()
		if err != nil {
			u.logger.Error("GeoIP update failed", "error", err)
			return
		}
		if !changed {
			u.logger.Info("GeoIP database unchanged (ETag match)")
			return
		}
		u.reloadDB()
	})
	if err != nil {
		return fmt.Errorf("invalid cron expression %q: %w", u.cronExpr, err)
	}

	u.cron.Start()
	u.logger.Info("GeoIP auto-update scheduled", "cron", u.cronExpr, "source", u.source.Source)

	<-ctx.Done()
	u.cron.Stop()
	return nil
}

func (u *Updater) validate() error {
	switch u.source.Source {
	case SourceP3TERX:
		return nil
	case SourceMaxmind:
		if u.source.LicenseKey == "" {
			return errors.New("FIREFIK_GEOIP_SOURCE=maxmind requires FIREFIK_GEOIP_LICENSE_KEY")
		}
		return nil
	case SourceURL:
		if u.source.DownloadURL == "" {
			return errors.New("FIREFIK_GEOIP_SOURCE=url requires FIREFIK_GEOIP_DOWNLOAD_URL")
		}
		return nil
	default:
		return fmt.Errorf("unknown FIREFIK_GEOIP_SOURCE %q", u.source.Source)
	}
}

func (u *Updater) downloadIfMissing() error {
	if _, err := os.Stat(u.dbPath); err == nil {
		return nil
	}
	u.logger.Info("GeoIP database not found, downloading", "path", u.dbPath, "source", u.source.Source)
	changed, err := u.download()
	if err != nil {
		return err
	}
	if changed {
		u.reloadDB()
	}
	return nil
}

func resolveDownloadURL(src SourceConfig) (url string, archived bool, err error) {
	switch src.Source {
	case SourceP3TERX:
		return p3terxDownloadURL, false, nil
	case SourceMaxmind:
		if src.LicenseKey == "" {
			return "", false, errors.New("maxmind source requires license key")
		}
		return fmt.Sprintf(maxmindDownloadURL, src.LicenseKey), true, nil
	case SourceURL:
		if src.DownloadURL == "" {
			return "", false, errors.New("url source requires download URL")
		}
		return src.DownloadURL, strings.HasSuffix(src.DownloadURL, ".tar.gz") || strings.HasSuffix(src.DownloadURL, ".tgz"), nil
	default:
		return "", false, fmt.Errorf("unknown source %q", src.Source)
	}
}

func (u *Updater) download() (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	url, archived, err := resolveDownloadURL(u.source)
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", u.userAgent())
	if etag := u.loadETag(); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("download GeoIP: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return false, nil
	default:
		return false, fmt.Errorf("download GeoIP: HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(u.dbPath), 0o755); err != nil {
		return false, fmt.Errorf("create directory: %w", err)
	}

	tmpFile := u.dbPath + ".tmp"
	if archived {
		if err := extractMMDB(resp.Body, tmpFile); err != nil {
			_ = os.Remove(tmpFile)
			return false, fmt.Errorf("extract GeoIP: %w", err)
		}
	} else {
		if err := writeRawMMDB(resp.Body, tmpFile); err != nil {
			_ = os.Remove(tmpFile)
			return false, fmt.Errorf("write GeoIP: %w", err)
		}
	}

	if err := os.Rename(tmpFile, u.dbPath); err != nil {
		_ = os.Remove(tmpFile)
		return false, fmt.Errorf("rename GeoIP db: %w", err)
	}

	u.storeETag(resp.Header.Get("ETag"))
	u.logger.Info("GeoIP database updated", "path", u.dbPath, "source", u.source.Source)
	return true, nil
}

func writeRawMMDB(r io.Reader, destPath string) error {
	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func extractMMDB(r io.Reader, destPath string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if strings.HasSuffix(hdr.Name, ".mmdb") {
			f, err := os.Create(destPath)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		}
	}
	return fmt.Errorf("no .mmdb file found in archive")
}

func (u *Updater) etagPath() string {
	return u.dbPath + ".etag"
}

func (u *Updater) loadETag() string {
	data, err := os.ReadFile(u.etagPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (u *Updater) storeETag(etag string) {
	if etag == "" {
		_ = os.Remove(u.etagPath())
		return
	}
	_ = os.WriteFile(u.etagPath(), []byte(etag), 0o644)
}

func (u *Updater) userAgent() string {
	v := u.source.Version
	if v == "" {
		v = "dev"
	}
	return "firefik/" + v
}

func (u *Updater) reloadDB() {
	db, err := Open(u.dbPath)
	if err != nil {
		u.logger.Error("failed to open updated GeoIP database", "error", err)
		return
	}
	if u.onUpdate != nil {
		u.onUpdate(db)
	}
}
