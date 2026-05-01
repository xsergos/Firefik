# Contributing to firefik

Thanks for the interest. Firefik is a small, focused project — we prefer
clear, narrow contributions over wide refactors.

## Ground rules

- **Linux-only by design.** iptables/nftables are Linux kernel APIs;
  Windows / macOS host support is permanently out of scope.
- **No HA, no multi-host federation, no Postgres.** These are
  permanently out of scope; please open a discussion before
  proposing architectural changes that assume otherwise.
- **Kernel is the source of truth.** Anything that mutates iptables/
  nftables must survive a firefik restart and be re-derivable from
  container labels + policies.

## Development loop

```bash
cd backend && go test ./... -race
cd frontend && npm test -- --run && npm run type-check && npm run lint
```

Integration tests (require `CAP_NET_ADMIN` + Docker):

```bash
cd backend && go test -tags=integration ./tests/integration/...
```

## Commit convention

We use conventional commits — the release automation parses them.

| Prefix | When to use |
|---|---|
| `feat:` | New user-visible capability |
| `fix:` | Bug fix (kernel-state correction, UI regression, …) |
| `docs:` | Documentation only |
| `chore:` | Build, CI, deps |
| `refactor:` | Internal restructure, no behaviour change |
| `test:` | Tests only |
| `perf:` | Performance-only change with measurement |

Breaking changes: suffix with `!` (e.g. `feat!:`) **and** add a
`BREAKING CHANGE:` footer describing migration.

## Pull request checklist

- [ ] `go test ./... -race` green.
- [ ] `npm test && npm run type-check && npm run lint` green.
- [ ] Coverage for touched packages does not regress.
- [ ] New env-vars added to `docs/reference.md`.
- [ ] New metrics added to `docs/metrics-guide.md` (+ alert rule if
      actionable).
- [ ] If adding a non-obvious trade-off: one paragraph in the PR
      description explaining the alternatives considered.
- [ ] No emojis, no `TODO:` comments, no `fmt.Println` debugging left
      behind.

## Review process

- At least one maintainer review before merge.
- Squash-merge by default; preserve Co-authored-by lines for pair work.
- CI must be green (govulncheck, gosec, trivy, openapi-check, build).

## Security-sensitive changes

Anything touching auth, mTLS, CA, or kernel-rule emission requires:

- Test covering both the happy path and the reject/deny path.
- If audit semantics change, document the rationale in the PR
  description.
- See `SECURITY.md` for how to report vulnerabilities privately.
