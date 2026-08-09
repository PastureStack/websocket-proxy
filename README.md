# PastureStack WebSocket Proxy

WebSocket Proxy bridges node backends and compatible control-platform clients for logs, statistics, exec, console, Docker socket, container proxy, subscription, and API-interceptor traffic.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/websocket-proxy`](https://github.com/rancher/websocket-proxy). This GitHub fork preserves upstream history, authorship, dates, tags, licenses, and bundled dependency notices; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Project status

The reviewed source produces the numeric-version candidate `v0.23.13`. It uses
Go 1.26.5 and Docker CLI 29.6.2, a digest-locked Ubuntu 26.04 build image, a
dated Ubuntu snapshot, exact direct-package versions, and checksum-verified
toolchain archives. Product-owned imports, configuration fields, proxy
identifiers, filter filenames, and operator messages use PastureStack naming.
The repository does not publish packages or deploy a service automatically.

The compatibility update also replaces the generated legacy API client and
old TLS, UUID, configuration, and error helpers with narrowly scoped standard
library code. Certificate discovery remains schema-driven, but every request
has a timeout, bounded response size, authenticated same-origin URL policy,
status validation, and bounded ZIP extraction. TLS listeners require TLS 1.2
or newer. Current vendored dependency provenance is recorded in
[`vendor/UPSTREAM.md`](vendor/UPSTREAM.md).

## Configuration

Use `--platform-address`, `PLATFORM_ACCESS_KEY`, and `PLATFORM_SECRET_KEY`. Historical `--cattle-address`, `PROXY_CATTLE_ADDRESS`, and `CATTLE_*` settings remain compatibility fallbacks. Set `PASTURESTACK_LOCALE=en-US` or `zh-TW` for operator messages.

The persistent console broker uses
`/v1/exec/sessions/{sessionId}`. Session creation and deletion require a
same-origin request; WebSocket attachment authenticates with the
`pasturestack-console-v1`, `pasturestack-secret.<secret>`, and
`pasturestack-client.<clientId>` subprotocols. Secrets and backend tokens are
not placed in public URLs. Replay, client count, active retention, ended-session
retention, and total sessions are bounded.

## Build and test

From a Docker-capable Linux host:

```sh
make test
make build
make package
```

Set `VERSION_OVERRIDE=v0.23.13` for this reviewed candidate. Packaging rejects
brand or maintenance suffixes and produces the deterministic,
versioned `websocket-proxy-0.23.13-linux-amd64.tar.xz` asset. Creating a Git
tag, Release, or published package remains a separate explicit decision.

See [COMPATIBILITY.md](COMPATIBILITY.md), [SECURITY.md](SECURITY.md), and [ORIGIN.md](ORIGIN.md).

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). Copyright and attribution for inherited work and vendored dependencies remain with their respective authors and contributors. PastureStack contributors claim authorship only for their own changes.
