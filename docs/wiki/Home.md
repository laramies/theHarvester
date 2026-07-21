# theHarvester wiki

theHarvester gathers open-source intelligence about a domain or organization from search engines, certificate transparency logs, DNS datasets, code repositories, threat-intelligence platforms, and other public sources.

Use it for the early reconnaissance stage of an authorized security assessment. Passive providers still receive the search target, while DNS brute force, DNS resolution, takeover checks, screenshots, and API-path scanning create additional network activity. Use those features only on systems you own or are explicitly authorized to test.

## Start here

1. [Install theHarvester](Installation).
2. Follow the [Quick Start](Quick-Start) for a small passive run.
3. Read [Responsible Use and Scope](Responsible-Use-and-Scope) before enabling active features.
4. Add credentials through [Configuration and API Keys](Configuration-and-API-Keys) when a selected provider requires them.
5. Learn where findings are stored in [Results and Local Data](Results-and-Local-Data).

## Choose an interface

- **Command line:** best for interactive reconnaissance and report generation.
- **REST API:** best for local integrations and browser-accessible Swagger/ReDoc documentation. See [REST API](Rest-API).
- **Docker Compose:** runs the REST API service, not the normal interactive CLI.

The repository [README](https://github.com/laramies/theHarvester) owns the current feature summary and source/result matrix. The live `theHarvester -h` output owns the complete CLI reference.

## Project credit

[Christian Martorella (@laramies)](https://twitter.com/laramies) created theHarvester. Contact: [cmartorella@edge-security.com](mailto:cmartorella@edge-security.com).

See the repository README for current maintainers and contributors.
