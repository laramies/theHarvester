# Security Policy

## Supported versions

Security reports are accepted for the current `master` branch and the latest published release. Fixes are developed against `master`; backports to older releases are not guaranteed.

## Report a vulnerability

Do not disclose suspected vulnerabilities, exploit details, credentials, private target data, or raw API responses in a public issue or pull request.

If the repository's **Security** tab offers **Report a vulnerability**, use that private form. If no private form is available, open a minimal issue asking the maintainers for a private reporting contact. Include no vulnerability details in that issue.

In the private report, provide:

- the affected version or commit;
- the security impact and affected component;
- minimal reproduction steps or proof of concept;
- any suggested mitigation;
- whether you want public credit.

Use only systems and accounts you own or are explicitly authorized to test. Stop if testing could access, modify, retain, or expose another party's data. Do not use third-party targets to demonstrate a vulnerability in theHarvester.

## Scope

This policy covers vulnerabilities in theHarvester's code, dependencies, packaging, and repository automation. Vulnerabilities in third-party data providers or services should be reported to those providers through their own security channels.

Provider outages, rate limits, data quality, and ordinary functional bugs are not security vulnerabilities. Report those through the normal issue tracker after removing credentials, account information, private target data, and unnecessary response content.

## Disclosure

Allow the maintainers a reasonable opportunity to investigate and release a fix before public disclosure. The project may coordinate an advisory or CVE when appropriate and will credit reporters who request acknowledgement.

This project does not currently offer a bug bounty or guarantee monetary rewards.
