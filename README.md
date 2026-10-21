# PastureStack WebSocket Proxy

WebSocket Proxy bridges node backends and compatible control-platform clients for logs, statistics, exec, console, Docker socket, container proxy, subscription, and API-interceptor traffic.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

## Capabilities

The source package version is `0.23.16`, rebuilt with Go 1.27.3 for the crypto/x509 fix CVE-2026-111943. Target-bound API Key tickets require exact target, operation, revision, expiry, and ticket digest matches from the trusted Engine. Handshake and periodic live checks fail closed. Persistent console secrets cannot extend an expired or revoked ticket; revocation also clears replay data. Legacy and full-without-expiry token authentication remains unchanged.

Every verified API Key stream requires an authenticated Host API `0.38.5` connection declaring `key-audit-v1,key-delegation-v1`. Missing capabilities prevent forwarding any execution payload. The Proxy submits only the signed stream ticket and that connection's signed backend ticket to the Engine's fixed audit-only failure endpoint; it returns `BackendAuditCapabilityUnavailable` (503) only after durable acceptance, or `AuditUnavailable` (503) when evidence cannot be accepted. Ordinary non-Key streams do not gain this capability requirement.

An expired, signed Key-traced ticket is rejected before creating a backend or persistent session. Its fixed denial receipt uses the ticket's verified identity and an authenticated host proof; signature-only parsing is never an authorization path. Each handshake attempt has a separate audit receipt. Tokens without verified Key attribution retain their existing authentication behavior and cannot claim someone else's audit history.

Certificate discovery is schema-driven with bounded responses, timeouts, same-origin URL checks, and bounded ZIP extraction. TLS listeners require TLS 1.2 or newer. Dependency provenance is recorded in `go.mod`, `go.sum`, `vendor/modules.txt`, and [`DEPENDENCIES.md`](DEPENDENCIES.md).

## Configuration

Use `--platform-address`, `PLATFORM_ACCESS_KEY`, and `PLATFORM_SECRET_KEY`. Historical `--cattle-address`, `PROXY_CATTLE_ADDRESS`, and `CATTLE_*` settings remain compatibility fallbacks. Set `PASTURESTACK_LOCALE=en-US` or `zh-TW` for operator messages.

When TLS terminates in front of the Server container, set
`PROXY_PLATFORM_PUBLIC_ORIGIN` to the exact public origin, for example
`https://stack.example.com`. The proxy uses it only when the request host
matches that configured authority, so internal HTTP hops retain public HTTPS
links without trusting browser-supplied forwarding headers.

The persistent console broker uses
`/v1/exec/sessions/{sessionId}`. Session creation and deletion require a
same-origin request; WebSocket attachment authenticates with the
`pasturestack-console-v1`, `pasturestack-secret.<secret>`, and
`pasturestack-client.<clientId>` subprotocols. Secrets and backend tokens are
not placed in public URLs. Replay, client count, active retention, ended-session
retention, and total sessions are bounded.

## Build and test

From a Docker-capable Linux host, the checksum-pinned builder uses Go `1.27.3`:

```sh
make test
make build
make package
```

The default producer version is `0.23.16`; `VERSION_OVERRIDE` accepts only numeric semantic versions. Packaging
rejects brand or maintenance suffixes and produces the deterministic,
versioned `websocket-proxy-0.23.16-linux-amd64.tar.xz` asset. Install it with the matching official Engine and host-api package; scoped stream protection cannot be provided by replacing the proxy alone. Package publication and deployment are explicit operations.

See [COMPATIBILITY.md](COMPATIBILITY.md), [SECURITY.md](SECURITY.md), and [ORIGIN.md](ORIGIN.md).

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). Copyright and attribution for inherited work and vendored dependencies remain with their respective authors and contributors. PastureStack contributors claim authorship only for their own changes.
