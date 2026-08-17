# Quick start

These examples use the IANA-reserved `example.com` domain to show command syntax. Passive providers still receive the target string. Replace it only with a target that is within your authorized scope.

## Run a small passive query

From a source checkout:

Network activity: provider-facing passive lookups.

```bash
uv run theHarvester -d example.com -b crtsh,certspotter
```

From Kali or another installed package, omit `uv run`:

```bash
theHarvester -d example.com -b crtsh,certspotter
```

This queries two passive certificate sources and prints consolidated findings. An empty result can mean that the providers found nothing; it does not by itself prove that the run failed.

## Save a report

Network activity: provider-facing passive lookups plus local report writes.

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

This writes `report.jsonl` for automation and interchange. It also writes `report.json` and `report.xml` compatibility reports. The JSONL summary records source outcomes and evidence status, which distinguish a normal empty result from incomplete or failed work. See [Results and Local Data](Results-and-Local-Data).

## Resolve discovered hosts

DNS resolution creates additional network activity. Use it only within scope:

Network activity: provider-facing discovery followed by resolver-facing DNS queries.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh,certspotter -r
```

Pass a resolver IP, comma-separated resolver IPs, or a resolver file you create with one IP per line:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r resolvers.txt
```

## Choose sources deliberately

1. Use the [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources) to find sources that return the result types you need.
2. Start with a small source set. `-b all` contacts many independent services, can consume quotas, and makes provider failures harder to isolate.
3. Use `theHarvester -h` for the current option and source list.
