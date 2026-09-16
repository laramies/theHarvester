# theHarvester wiki

theHarvester gathers open-source intelligence about a domain or organization. It queries search engines, certificate transparency logs, DNS datasets, code repositories, threat-intelligence platforms, and other public sources.

Use it during the early reconnaissance stage of an authorized security assessment. Passive providers still receive the search target.

DNS brute force, DNS resolution, virtual host discovery, takeover checks, screenshots, and API-path scanning create additional network activity. Use these features only on systems you own or are explicitly authorized to test.

## Start here

1. [Install theHarvester](Installation).
2. Read [Responsible Use and Scope](Responsible-Use-and-Scope) before choosing a target or feature.
3. Follow the [Quick Start](Quick-Start) for a small passive run.
4. Add credentials through [Configuration and API Keys](Configuration-and-API-Keys) when a selected provider requires them.
5. Learn where findings are stored in [Results and Local Data](Results-and-Local-Data).

Coming from the 4.11 release line? Read [Moving from 4.11 to 5.0](Moving-from-4.11-to-5.0) before updating automation or saved-run reports.

## Choose an interface

| Interface | Use it for |
| --- | --- |
| Command line | Interactive reconnaissance and report generation. |
| HarvestView | Creating and inspecting durable local runs in a browser. See [REST API](Rest-API). |
| REST API | Authenticated local integrations and the generated Swagger/ReDoc reference. See [REST API](Rest-API). |
| Docker Compose | Running HarvestView and the REST API. It does not provide the normal interactive CLI. |

The repository [README](https://github.com/laramies/theHarvester) owns the current feature summary and source/result matrix. The live `theHarvester -h` output owns the complete CLI reference.

## Project credit

[Christian Martorella (@laramies)](https://twitter.com/laramies) created theHarvester. Contact: [cmartorella@edge-security.com](mailto:cmartorella@edge-security.com).

See the repository README for current maintainers and contributors.
