# Preserve discovery coverage and evidence

Provider responses can mix overlapping observations, status signals, and incomplete coverage. Adapters deduplicate the unit that consumes the result limit while retaining evidence that can still contribute a different observation. Coverage failures take precedence over an ordinary stop at the operator's limit so the source runner can report incomplete execution with the evidence it already collected.

## Provider decisions

- **DarkEye.** Each product has its own credential. Either credential enables the source for that product. The two products can index the same leak. Deduplicate the shared record identity while retaining its displayed product and category. The Have I Been Ransomed? adapter accepts the documented nested response and the observed top-level layout, and normalizes the requested domain before querying a provider that supports wildcard syntax. Breach House matches free text, so a reference to the target is insufficient when the website field identifies another domain. A title can supply the domain only at a hostname boundary when there is no website. Unreadable entries or failures from one product take precedence over another product's successful result.
- **FullHunt.** Domain details come first because that response carries more evidence. The dedicated subdomain lookup is a fallback for an empty hostname set.
- **Hudson Rock.** An email target also supplies a related domain to search. The domain and email requests serve different evidence routes.
- **Mojeek.** Separate linked result snippets from the text used to classify provider messages. A query result can quote error language, while the surrounding container can carry an actual provider message.
- **OTI Labs.** Pending enrichment can leave the response with fewer address observations than a later run. Report the provider's pending state as partial.
- **Outcrawl.** A URL counts once against the shared limit. Different snippets for that URL remain available to the parser because they can contain different evidence.
- **Profundis.** Read the actual newline-delimited frames despite the event-stream content type. Continue through the end because a credit snapshot can be followed by an error. Preserve errors even when later frames report credits.
- **ScanMalware.** Browser-contact observations serve a different purpose from names mentioned in the archive. Count distinct in-scope hostnames across scans and report degraded certificate transparency coverage ahead of an operator-limit completion.
- **Serply.** A body containing a provider refusal can arrive as an HTTP success. Interpret it as a failed request before checking the ordinary result shape.
- **Tomba.** The provider can supply a bare hostname in a source website field. Treat it as a network-path reference when parsing so it can pass through the same exact target-scope filter as an absolute URL.

The `MissingKey` exception remains an alias for `MissingKeyError` to preserve existing imports. The Pentest-Tools adapter uses the provider's [documented Subdomain Finder tool identity](https://pentest-tools.com/docs/api-reference/scans/start-a-scan) so the provider performs the selected operation.
