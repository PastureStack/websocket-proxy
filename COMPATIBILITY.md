# Compatibility Contract

The migration preserves existing `/v1`, `/v2-beta`, and `/v2` proxy paths, backend connection routes, subscription behavior, token validation inputs, generated client schemas, and proxy-protocol handling.

Preferred settings use `platform-*`, `PLATFORM_*`, and
`PROXY_PLATFORM_ADDRESS`. Historical `cattle-*`, `CATTLE_*`, and
`PROXY_CATTLE_ADDRESS` aliases remain only as runtime configuration contracts.
The generated legacy API client is no longer shipped. Its required certificate
discovery behavior is implemented against the compatible schema and credential
links with authenticated same-origin requests.

The persistent console endpoint adds `POST`, status `GET`, WebSocket `GET`, and
`DELETE` handling at `/v1/exec/sessions/{sessionId}`. Existing direct exec and
log proxy routes remain available. The broker preserves terminal output for a
bounded ended-session retention window so a client can inspect the final replay
without keeping the backend command alive.

Operator lifecycle messages support `en-US` and `zh-TW`. Proxied HTTP bodies, WebSocket frames, headers, tokens, log streams, identifiers, and backend errors are not translated.

Before release, validate every route family, backend reconnect, persistent
session create/attach/replay/delete/expiry, HTTP and WebSocket forwarding,
token-cookie and authorization-header flows, schema-driven certificate
download, TLS minimum version, proxy protocol, parent-process shutdown, and
error redaction.
