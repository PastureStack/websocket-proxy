# Dependency provenance

The repository builds in Go module vendor mode. `go.mod` and `go.sum` are the
machine-readable version and checksum authority; `vendor/modules.txt` binds the
exact offline build input. Normal builds do not download dependencies.

| Import path | Version | Purpose |
| --- | --- | --- |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | JWT validation |
| `github.com/gorilla/mux` | `v1.8.1` | HTTP routing |
| `github.com/gorilla/websocket` | `v1.5.3` | WebSocket protocol implementation |
| `github.com/sirupsen/logrus` | `v1.10.1` | Structured logging |
| `golang.org/x/sys` | `v0.47.0` | Operating-system interfaces used by logging |
| `gopkg.in/check.v1` | `v1.0.0-20201130134442-10cb98267c6c` | Test-only assertions |

Checksums and complete transitive dependencies are deliberately not duplicated
here; `go.sum` and `vendor/modules.txt` are the canonical records.
