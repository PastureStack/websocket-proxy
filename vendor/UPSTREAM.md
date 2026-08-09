# Vendored dependency provenance

The repository is built in GOPATH vendor mode for compatibility with the
preserved service layout. `trash.conf` is the human-readable version lock; this
file records the exact reviewed source revisions and license-file checksums.
No dependency is downloaded during the normal build.

| Import path | Version | Exact source revision | License file SHA-256 | Purpose |
| --- | --- | --- | --- | --- |
| `github.com/sirupsen/logrus` | `v1.9.4` | `b61f268f75b6ff134a62cd62aee1095fa12e8d2e` | `51a0c9ec7f8b7634181b8d4c03e5b5d204ac21d6e72f46c313973424664b2e6b` | Structured logging |
| `golang.org/x/sys` | `v0.43.0` | `f33a730cd0c449cfd6f7106780c73052e96cc33d` | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` | Operating-system interfaces used by logging |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | `7ceae619e739dc8a7bf577214aa8ebf26668e9db` | `fe26ca41577b9b2b4448050a24b25e5753af66b5d5945d5d36094e7790bfcb2f` | JWT validation |
| `github.com/gorilla/mux` | `v1.8.1` | `b4617d0b9670ad14039b2739167fd35a60f557c5` | `0b77fdea862f869ef4f201ac5649bdbd38ccb055c7f6454dffae9e2adb4941c1` | HTTP routing |
| `github.com/gorilla/websocket` | `v1.5.3` | `ce903f6d1d961af3a8602f2842c8b1c3fca58c4d` | `2be1b548b0387ca8948e1bb9434e709126904d15f622cc2d0d8e7f186e4d122d` | WebSocket protocol implementation |
| `github.com/patrickmn/go-cache` | `v2.1.0` | `a3647f8e31d79543b2d0f0ae2fe5c379d72cedc0` | `0070a164e0fc28e82739a764c37b38c56de796f9a8d1862b4413eb6978cd4e04` | Bounded token cache |
| `gopkg.in/check.v1` | commit | `4f90aeace3a26ad7021961c297b22c42160c7b25` | `69ce77f2b1c9c608d27f2d749b0e7d0c13960ed3b0dc07b973ac940e362e5d9c` | Test-only assertions |

The compatibility update removed the generated legacy control-platform API
client, the Docker TLS helper, the time-based UUID library, the configuration
wrapper, and the error wrapper. Their small required behaviors are now covered
by the Go standard library and repository tests. This reduces the transitive
source and keeps certificate retrieval, TLS policy, UUID generation, and error
wrapping locally auditable.
