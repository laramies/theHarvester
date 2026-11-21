# Respect provider pagination and retry boundaries

Provider page sizes, offset ceilings, account quotas, and request deadlines define how much a source can inspect independently of the operator's result limit. Adapters use the provider's pagination signals and keep only the evidence the operator requested. When a provider ceiling cuts short coverage, the adapter reports that boundary explicitly. These constraints keep uncapped discovery finite and preserve a distinction between exhaustion and incomplete coverage.

## Provider windows

- **Brave and ScanMalware.** Brave's documented offsets run from zero through nine. ScanMalware's certificate transparency and search lookups have separate provider maxima.
- **Common Crawl.** The CDX `limit` parameter truncates captures inside a ZipNum page. Fetch each bounded page and apply the result limit after extracting distinct hostnames, since earlier captures may all refer to the same host.
- **DarkEye.** The Have I Been Ransomed? page guard follows the provider's aggregate search bound. A short or empty page can occur before the end because records without metadata are omitted. Follow `has_next` and deduplicate provider IDs across pages because newly indexed records can shift earlier results into a later page.
- **Hunter and Tomba.** A free account check determines which requests a plan supports. Hunter's paid branch uses a separate count and the provider's [domain-search page size](https://hunter.io/api-documentation/v2#domain-search) to budget calls.
- **Netlas.** Counts above 1,000 can be estimates within 3%. The adapter uses the upper bound when planning pages so an underestimate does not hide results.
- **Outcrawl.** A ranked window can supply at most twenty hits with no offset for fetching later rows. A full window may hide additional results. The request budgets space for URLs already seen in the other window, so duplicates can still incur a per-row cost.
- **Serply.** The provider advances with `start`. Its requested count is approximate and ten pages per query bound the conversation. Search windows can overlap, so inspect the whole page for fresh links before applying the local limit. A page that contributes no fresh links stops the query.

## Pacing and interruptions

GitHub Code Search recognizes rate-limit headers on a 403 and uses the provider's [one-minute fallback guidance](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api#exceeding-the-rate-limit) when there is no deadline. It ends the source for waits beyond its bound to keep the run finite. Hudson Rock retries explicit HTTP 429 responses. The shared transport returns a missing response for transport failures, so Hudson Rock treats that signal as terminal. Shodan's asynchronous REST client preserves the official SDK's one-request-per-second limit after replacing its blocking transport.
