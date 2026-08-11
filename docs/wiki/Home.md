# theHarvester wiki

theHarvester gathers open-source intelligence about a domain or organization. It queries search engines, certificate transparency logs, DNS datasets, code repositories, threat-intelligence platforms, and other public sources.

Use it during the early reconnaissance stage of an authorized security assessment. Passive providers still receive the search target.

DNS brute force, DNS resolution, virtual host discovery, takeover checks, screenshots, and API-path scanning create additional network activity. Use these features only on systems you own or are explicitly authorized to test.

## Start here

1. [Install theHarvester](Installation).
2. Follow the [Quick Start](Quick-Start) for a small passive run.
3. Read [Responsible Use and Scope](Responsible-Use-and-Scope) before enabling active features.
4. Add credentials through [Configuration and API Keys](Configuration-and-API-Keys) when a selected provider requires them.
5. Learn where findings are stored in [Results and Local Data](Results-and-Local-Data).

## Choose an interface

- **Command line:** best for interactive reconnaissance and report generation.
- **HarvestView:** best for creating and inspecting durable local enumeration runs in a browser. See [REST API](Rest-API).
- **REST API:** best for authenticated local integrations and Swagger/ReDoc documentation. See [REST API](Rest-API).
- **Docker Compose:** packages HarvestView and the REST API, not the normal interactive CLI.

The repository [README](https://github.com/laramies/theHarvester) owns the current feature summary and source/result matrix. The live `theHarvester -h` output owns the complete CLI reference.

## Project credit

[Christian Martorella (@laramies)](https://twitter.com/laramies) created theHarvester. Contact: [cmartorella@edge-security.com](mailto:cmartorella@edge-security.com).

See the repository README for current maintainers and contributors.
