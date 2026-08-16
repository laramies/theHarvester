# Quick start

These examples use the IANA-reserved `example.com` domain as inert test data. Replace it only with a target that is within your authorized scope.

## Run a small passive query

From a source checkout:

```bash
uv run theHarvester -d example.com -b crtsh,certspotter
```

From Kali or another installed package, omit `uv run`:

```bash
theHarvester -d example.com -b crtsh,certspotter
```

This queries two passive certificate sources and prints consolidated findings. Passive does not mean private: the selected providers receive the target string.

## Save a report

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

This writes `report.jsonl` for automation and interchange. It also writes legacy `report.json` and `report.xml` compatibility reports. See [Results and Local Data](Results-and-Local-Data).

## Resolve discovered hosts

DNS resolution creates additional network activity. Use it only within scope:

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

The [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources) shows the result types and credential requirements for every current source.

Do not start with `-b all`. It contacts many independent services and can consume quotas. It also increases runtime and makes provider failures harder to isolate.

Choose a small group of sources that provides the result types you need.

Use `theHarvester -h` for the current option and source list.
