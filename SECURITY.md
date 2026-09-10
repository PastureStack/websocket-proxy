# Security Policy

## Supported state

The source is a reviewed compatibility candidate. It is not a production
support commitment and is not published or deployed automatically.

## Security boundaries

- JWT keys, API credentials, tokens, cookies, certificates, proxied headers, and body content are sensitive.
- Access logs contain paths only. Query strings, authentication cookies, proxy
  authorization headers, raw headers, bodies, terminal output, and token
  fingerprints must never be written to logs.
- Browser WebSocket upgrades are same-origin. Non-browser backends may omit the
  `Origin` header, but a supplied cross-origin value is rejected.
- Authentication query parameters and cookies are consumed by the proxy and
  are not forwarded to container HTTP endpoints. Signed host-operation tokens
  are relayed only through the authenticated internal WebSocket path because
  the host endpoint independently authorizes each operation.
- Exec, console, Docker socket, logs, and container proxy routes can expose privileged node capabilities.
- Control-platform schema, credential, certificate, and JWT-key responses have
  explicit timeouts and size limits. Schema-advertised and credential-linked
  resources must remain on the configured origin; redirects are rejected.
- Certificate archives accept only one bounded `ca.pem`, `cert.pem`, and
  `key.pem`. TLS listeners require TLS 1.2 or newer.
- Persistent console sessions require same-origin mutation requests and
  high-entropy session, secret, and client identifiers. Secrets and backend
  tokens must never be placed in public URLs or logs.
- Session count, replay memory, client count, message size, active lifetime,
  ended-session retention, and cleanup intervals remain bounded.
- Proxy frames, interceptor request and response bodies, platform account
  responses, key files, master-address files, and service-proxy responses are
  bounded. Redirects are rejected for credential-bearing control-platform and
  interceptor requests.
- Client-supplied forwarding headers are replaced with the connection identity
  established by the listener; they are never trusted as authoritative input.
- A configured public origin may restore the external scheme and port after an
  internal HTTP hop, but only for requests whose host matches that exact
  administrator-configured authority.
- Proxy Protocol is accepted from loopback sources by default. Deployments
  using a remote load balancer must explicitly configure its source networks
  with `--trusted-proxy-cidrs` (or `PROXY_TRUSTED_PROXY_CIDRS`).
- Interceptor and alternate proxy destinations accept only explicit HTTP(S)
  URLs without embedded credentials or fragments. These destinations remain
  privileged administrator configuration because filters may receive request
  headers and bodies by design.
- Do not commit keys, credentials, tokens, certificates, interceptor secrets, or captured production traffic.

## Release gates

A release candidate must pass standard tests, race tests, static analysis,
dependency and license inventory, source secret scanning, and applicable
HIGH/CRITICAL vulnerability scans. The deterministic package must be built
twice from the same source and compared before any separate publication step.
Current release versions use numeric semantic versions only. Product or
maintenance names must not be appended to version numbers.

The reproducible builder uses Ubuntu's `linux-libc-dev` package only for
userspace API headers required by compilation and race tests. The delivered
artifact is a statically linked binary and does not contain that package or a
Linux kernel implementation. The release gate therefore scans the actual
distributable binary with Trivy and govulncheck, rather than treating the
build-only image as a runtime product. HIGH/CRITICAL findings in source
dependencies or the distributable binary remain release-blocking.

## Reporting

Report suspected vulnerabilities through this repository's private security advisory channel. Do not include credentials or production traffic in a public issue.
