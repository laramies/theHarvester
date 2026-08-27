# Scope proxy mode to HTTP transport

Status: accepted

`--proxies` requires supported HTTP(S) provider and target requests to use one configured proxy identity and fail closed rather than fall back to direct HTTP(S). DNS queries remain independent resolver traffic: they use the operator-selected recursive resolver addresses and may coexist with proxied HTTP(S) in the same run. This accepts that the resolver and local network can observe DNS traffic, avoids implying that proxy mode provides anonymity, and keeps HTTP-only actions that cannot honor the proxy requirement unavailable in proxy mode.
