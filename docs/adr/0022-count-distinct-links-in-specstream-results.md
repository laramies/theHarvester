# Count distinct links in SpecStream search results

SpecStream can return the same URL in both the exact-match and site searches, sometimes with different titles or snippets. A URL counts once toward the operator’s result limit. Distinct text for that URL still goes to the parser because it can contain evidence absent from the first result.

The adapter keeps the requested page size fixed within each query so that later pages continue the same result list. It trims surplus rows locally. A next-page cursor beyond the provider’s ten-page window indicates incomplete coverage of that query. If the searches finish without reaching an operator result limit after encountering that boundary, the adapter reports partial coverage. This also applies to uncapped runs.
