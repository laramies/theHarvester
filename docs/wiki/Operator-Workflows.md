# Operator workflows

Start with the smallest source set and least active behavior that can answer the engagement question. Replace `example.com` only with an authorized target.

## Passive subdomain discovery

```bash
uv run theHarvester -d example.com -b crtsh,certspotter,commoncrawl
```

Use the [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources) to choose complementary sources. Adding every source usually increases noise, rate-limit failures, and runtime more than it improves a focused run.

## Save results for automation

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

Use `report.json` for automation and `report.xml` for the smaller legacy host/email representation. See [Results and Local Data](Results-and-Local-Data).

## DNS resolution

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh,certspotter -r
```

To control the resolvers used:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r resolvers.txt
```

Resolver files contain one IP address per line. DNS requests disclose candidate names to the selected resolver.

## Shodan enrichment

Configure the Shodan key, then enrich resolved hosts:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r -s
```

Shodan output is enrichment after discovery and is separate from what most discovery sources add to the consolidated result columns.

## DNS brute force

Use only an owned or explicitly authorized target:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -c
```

DNS brute force actively tests candidate names. Do not run it against `example.com` or an unrelated third-party domain.

## Takeover checks

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh,certspotter -t
```

Treat matches as leads requiring manual confirmation. Do not claim a takeover from a fingerprint match alone.

## Screenshots

Install Chromium first, then choose an output directory:

```bash
uv run playwright install chromium
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r --screenshot screenshots
```

Screenshots actively open discovered web services and may retain sensitive page content.

## API-path scanning

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -a
```

Provide a custom path wordlist with `-w FILE`. This sends requests directly to the target and must be explicitly in scope.

## Diagnose one provider

When a combined run fails, rerun only the affected source with a conservative result limit:

```bash
uv run theHarvester -d example.com -b source-name -l 10
```

Check the provider's current status, authentication requirements, rate limits, and terms before reporting a tool defect.
