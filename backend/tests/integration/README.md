# Integration tests

Kernel-level tests that drive the real `iptables` / `nftables`
backends. Unlike the package-level unit tests, these require
`CAP_NET_ADMIN` and mutate host networking state.

## Running

```bash
cd backend
sudo -E go test -tags=integration -timeout=5m ./tests/integration/...
```

The build tag `integration` keeps these out of `go test ./...` — no
collateral damage when running the regular suite on a developer
laptop.

## Safety

Each test picks a unique chain name `FIREFIKT<ns><n>` and registers
`t.Cleanup` that tears down its own kernel state even on failure.
This is namespaced enough to run alongside a live firefik on the same
host (though not recommended — a failing test may leave orphan chains
that require `iptables -F <chain>; iptables -X <chain>` or
`nft delete table inet firefik` to fully recover).

## CI

The `integration` job in `.github/workflows/ci.yml` runs the suite on
`ubuntu-24.04` GitHub runners, which have a current kernel and root.
If a test fails only in CI and not locally, the most likely causes are:

1. Kernel version drift — pin the runner (`ubuntu-24.04`, not `-latest`).
2. `iptables-nft` vs `iptables-legacy` alternative — CI installs the
   `iptables` package which defaults to `-nft` on Ubuntu 24.04.
