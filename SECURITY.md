# Security Policy

## Reporting a Vulnerability

If you've found a security issue in **nextgen-dast** itself (the orchestrator,
proxy, web UI, API, or database schema), please report it privately rather
than opening a public issue. Public disclosure of an unpatched vulnerability
in a security tool puts the tool's users at risk.

**Email:** `tim.j.rice@hackrange.com`

When reporting, include as much of the following as you can:

- The affected version (e.g. `2.1.1`) and the deployment surface (Docker
  image tag, host OS, reverse proxy in front).
- A clear description of the issue and its impact.
- Reproduction steps, a proof-of-concept request, or a minimal patch
  demonstrating the bug.
- Whether the issue is already public (CVE assigned, blog post, etc.) or
  embargoed.

You will receive an acknowledgement within **2 business days**. We aim to
deliver an initial assessment within **5 business days** of acknowledgement.

## Disclosure Process

1. We confirm the report and reproduce the issue.
2. We develop a fix on a private branch and prepare release notes.
3. We coordinate a disclosure date with the reporter. Default embargo is
   **30 days** from the date the fix is ready, extendable for severe issues
   that require downstream notification.
4. A patched image is published to
   `dockerregistry.fairtprm.com/nextgen-dast` and the source is pushed to
   the public git repository.
5. We credit the reporter in the release notes unless they request
   anonymity.

## Supported Versions

Only the latest minor release line receives security fixes.

| Version | Supported |
|---------|-----------|
| 2.1.x   | Yes       |
| < 2.1   | No        |

## Scope

In scope:

- The nextgen-dast application code under `app/`, `scripts/`, `toolkit/`,
  and `db/`.
- The Docker image build (`Dockerfile`) and the compose stack
  (`docker-compose.yml`).
- The setup and operational helpers (`setup.sh`, `pentest.sh`).
- Default credentials, weak secret generation, authentication and
  authorization flaws, SSRF, SQLi, XSS, RCE, path traversal,
  deserialization, broken access control, or any OWASP top-10 class issue
  in the application itself.

Out of scope (report upstream):

- Vulnerabilities in bundled third-party scanners (`wapiti`, `nikto`,
  `nuclei`, `testssl.sh`, `sqlmap`, `dalfox`, `ffuf`) — report to those
  projects directly.
- Vulnerabilities in MariaDB, Python, or any OS-level package — report to
  the upstream maintainers.
- Issues that require a malicious administrator with full shell access to
  the host or to the application's admin account.
- Findings produced *by* nextgen-dast against a target application — those
  are scan results, not tool vulnerabilities.

## Safe Harbor

We will not pursue civil or criminal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Do not access, modify, or destroy data belonging to other users of the
  software.
- Do not perform testing against production deployments they don't own or
  have explicit authorization to test.
- Give us reasonable time to respond before any public disclosure.

## Contact

- Security email: `tim.j.rice@hackrange.com`
- Project maintainer: Tim Rice
