# Keep HTTP session policy with the session owner

The default request path delegates TLS policy to a borrowed session's connector and reuses its context. A request with an explicit Boolean verification override retains that override. The session owner handles teardown, so callers also retain a way to observe unexpected cleanup errors separately from normalized transport failures during setup or requests.

A provider conversation keeps the cookies needed by later pages. DarkEye runs its two products in separate sessions so a product receives only its own authentication and cookies. Local tests use a hostname for cookie-dependent default aiohttp sessions because the default jar ignores cookies from numeric IP hosts.
