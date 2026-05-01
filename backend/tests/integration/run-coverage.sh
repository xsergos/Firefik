#!/bin/sh
set -eu

OUT_DIR=${OUT_DIR:-/coverage}
mkdir -p "$OUT_DIR"

# Ensure DOCKER-USER chain exists so firefik agent can attach its parent jump.
iptables -t filter -N DOCKER-USER 2>/dev/null || true
iptables -t filter -A DOCKER-USER -j RETURN 2>/dev/null || true
ip6tables -t filter -N DOCKER-USER 2>/dev/null || true
ip6tables -t filter -A DOCKER-USER -j RETURN 2>/dev/null || true

echo "==> unit tests (Linux build)"
go test -coverpkg=./... -coverprofile="$OUT_DIR/unit-linux.out" ./... 2>&1 | tail -3
go tool cover -func="$OUT_DIR/unit-linux.out" | tail -1

echo
echo "==> integration tests"
go test -tags=integration -coverpkg=./... -coverprofile="$OUT_DIR/integration.out" ./tests/integration/... 2>&1 | tail -5
go tool cover -func="$OUT_DIR/integration.out" | tail -1

echo
echo "==> binary coverage build"
COVER_BIN_DIR=/tmp/covbin
mkdir -p "$COVER_BIN_DIR"

go build -cover -covermode=set -coverpkg=./... -o /tmp/firefik-cov ./cmd/firefik
go build -cover -covermode=set -coverpkg=./... -o /tmp/firefik-server-cov ./cmd/firefik-server
go build -cover -covermode=set -coverpkg=./... -o /tmp/firefik-admin-cov ./cmd/firefik-admin

echo
echo "==> firefik agent boot (5s, with /var/run/docker.sock if mounted)"
GOCOVERDIR="$COVER_BIN_DIR" \
  FIREFIK_LISTEN_ADDR=":0" \
  FIREFIK_BACKEND=iptables \
  FIREFIK_API_TOKEN=test \
  FIREFIK_LOG_LEVEL=info \
  FIREFIK_PARENT_CHAIN=DOCKER-USER \
  FIREFIK_USE_GEOIP_DB=false \
  /tmp/firefik-cov &
PID=$!
sleep 5
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

echo
echo "==> firefik agent boot (nftables backend)"
GOCOVERDIR="$COVER_BIN_DIR" \
  FIREFIK_LISTEN_ADDR=":0" \
  FIREFIK_BACKEND=nftables \
  FIREFIK_API_TOKEN=test \
  FIREFIK_LOG_LEVEL=info \
  FIREFIK_PARENT_CHAIN=FORWARD \
  FIREFIK_USE_GEOIP_DB=false \
  FIREFIK_CHAIN_NAME=FIREFIK_NFT \
  /tmp/firefik-cov &
PID=$!
sleep 5
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

echo
echo "==> firefik agent boot (with bad config to exercise error paths)"
GOCOVERDIR="$COVER_BIN_DIR" \
  FIREFIK_LISTEN_ADDR=":0" \
  FIREFIK_BACKEND=iptables \
  FIREFIK_API_TOKEN_FILE=/nonexistent \
  /tmp/firefik-cov 2>/dev/null &
PID=$!
sleep 1
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

echo
echo "==> firefik-server boot (5s)"
GOCOVERDIR="$COVER_BIN_DIR" \
  /tmp/firefik-server-cov \
    -listen=":0" \
    -grpc-listen=":0" \
    -db=":memory:" \
    -ca-state-dir="" &
PID=$!
sleep 5
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

echo
echo "==> firefik-server backup/restore"
mkdir -p /tmp/cabackup /tmp/casrc
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-server-cov mini-ca init --state-dir=/tmp/casrc --trust-domain=spiffe://test/ 2>&1 | head -3 || true
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-server-cov backup --out=/tmp/cabackup/snap.tar --ca-state-dir=/tmp/casrc --db=:memory: 2>&1 | head -3 || true
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-server-cov restore --from=/tmp/cabackup/snap.tar --ca-state-dir=/tmp/casrc-restored --db=/tmp/casrc-restored.db 2>&1 | head -3 || true

echo
echo "==> firefik-server invalid args (error paths)"
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-server-cov backup 2>/dev/null || true
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-server-cov restore 2>/dev/null || true
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-server-cov mini-ca 2>/dev/null || true
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-server-cov mini-ca issue 2>/dev/null || true

echo
echo "==> firefik-admin commands"
for sub in '' '--help' '-h' 'help' 'unknown'; do
    GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-admin-cov $sub 2>/dev/null || true
done

# All subcommands with iptables backend (DOCKER-USER chain pre-created above).
for sub in 'status' 'check' 'inventory' 'doctor' 'reap --suffix=v1 --dry-run' \
           'metrics-audit' 'drain --confirm' 'force-reset' 'force-reset --confirm'; do
    GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-admin-cov $sub --backend=iptables 2>/dev/null || true
    GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-admin-cov $sub --backend=iptables --output=json 2>/dev/null || true
done
GOCOVERDIR="$COVER_BIN_DIR" /tmp/firefik-admin-cov reconcile --backend=iptables 2>/dev/null || true

echo
echo "==> binary coverage textfmt"
go tool covdata textfmt -i="$COVER_BIN_DIR" -o="$OUT_DIR/binary.out"
go tool cover -func="$OUT_DIR/binary.out" | tail -1

echo
echo "==> merging integration + binary into combined.out"
echo "mode: set" > "$OUT_DIR/combined.out"
grep -h -v '^mode:' "$OUT_DIR/integration.out" "$OUT_DIR/binary.out" \
    | sort -u >> "$OUT_DIR/combined.out"
go tool cover -func="$OUT_DIR/combined.out" | tail -1

echo
echo "==> done"
ls -la "$OUT_DIR"
