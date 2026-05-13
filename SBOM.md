# Software Bill of Materials — nextgen-dast 2.1.1

_Author: Tim Rice <tim.j.rice@hackrange.com>_

This document is the human-readable Software Bill of Materials (SBOM)
for the **nextgen-dast** application (image
`dockerregistry.fairtprm.com/nextgen-dast:2.1.1`). It summarizes
every third-party component that ships inside the application image
plus the MariaDB sidecar, with full machine-readable manifests in two
industry-standard formats committed alongside it:

| Format             | Spec version | File on disk            |
| ------------------ | ------------ | ----------------------- |
| **CycloneDX**      | 1.5 (JSON)   | [`sbom.cdx.json`](./sbom.cdx.json)   |
| **SPDX**           | 2.3 (JSON)   | [`sbom.spdx.json`](./sbom.spdx.json) |

Either JSON file can be ingested directly by SBOM tooling (Dependency-
Track, Trivy, Grype, FOSSology, OSV-Scanner, Anchore, Snyk, GitHub
dependency-graph, etc.). This Markdown file is the index — **the JSON
files are authoritative**. If they ever disagree, the JSON wins.

---

## Snapshot

- **Generated:** 2026-05-09
- **Image inspected:** `dockerregistry.fairtprm.com/nextgen-dast:2.1.1`
- **Image base:** `python:3.12-slim` (Debian 13 "trixie", amd64)
- **Sidecar:** `mariadb:11`
- **Resolution mode:** full transitive — `pip freeze`, `dpkg-query`,
  `npm ls -g` captured from the running container, augmented with
  binary tools / vendored data / base-image entries that none of
  those manifests cover.

### Component counts by ecosystem

| Ecosystem            | Count | Notes                                                                |
| -------------------- | ----: | -------------------------------------------------------------------- |
| Debian apt packages  |   669 | Includes the entire `python:3.12-slim` base + everything we add.     |
| Python (PyPI) wheels |   118 | Direct + transitive resolved by `pip` at image build time.           |
| Container images     |     2 | `python:3.12-slim` (FROM) and `mariadb:11` (compose service).        |
| Tool binaries        |     6 | `nuclei`, `dalfox`, `ffuf`, `osv-scanner`, `nikto`, `testssl.sh`.    |
| Vendored data        |     4 | Swagger UI, retire.js DB, nuclei-templates, SecLists web-content.    |
| npm globals          |     3 | `retire`, `yarn`, `pnpm` (used by SCA stage; not nested deps).       |
| **Total**            | **802** |                                                                    |

### License distribution (concluded)

| Identifier                                         | Count | Notes                                                          |
| -------------------------------------------------- | ----: | -------------------------------------------------------------- |
| NOASSERTION                                        |   670 | Mostly Debian packages — license metadata not embedded in dpkg. |
| MIT                                                |    53 |                                                                |
| BSD-3-Clause                                       |    35 |                                                                |
| Apache-2.0                                         |    18 |                                                                |
| GPL-2.0-only                                       |     5 | wapiti3, wapiti-swagger, sqlmap, nikto, testssl.sh, mariadb.   |
| BSD-2-Clause                                       |     4 |                                                                |
| PSF-2.0                                            |     3 | python interpreter, typing\_extensions, aiohappyeyeballs.      |
| Apache-2.0 OR MIT                                  |     3 |                                                                |
| Apache-2.0 OR BSD-3-Clause                         |     2 |                                                                |
| LGPL-3.0-only                                      |     2 | ldap3, browser-cookie3.                                        |
| ISC                                                |     2 | dnspython, socksio.                                            |
| MPL-2.0                                            |     1 | certifi.                                                       |
| MPL-2.0 OR MIT                                     |     1 | publicsuffix2.                                                 |
| GPL-2.0-or-later OR LGPL-2.1-or-later OR MPL-1.1   |     1 | pyphen.                                                        |
| LGPL-2.1-only                                      |     1 | urwid.                                                         |
| Apache-2.0 OR BSD-2-Clause                         |     1 | packaging.                                                     |

> **NOASSERTION caveat.** Debian packages do not expose a single SPDX
> identifier in their control metadata, so this generator does not
> guess. The license for any given Debian package is in
> `/usr/share/doc/<pkg>/copyright` inside the running container.
> Run a deeper scanner (Syft, ScanCode) against the live image if a
> license-accurate Debian sub-SBOM is required.

---

## Application metadata

| Field              | Value                                                            |
| ------------------ | ---------------------------------------------------------------- |
| Name               | `nextgen-dast`                                                   |
| Version            | `2.1.1`                                                          |
| Supplier / Author  | Tim Rice <tim.j.rice@hackrange.com>                              |
| Source repository  | <https://github.com/websecusa/nextgen-dast.git>               |
| Distribution       | `dockerregistry.fairtprm.com/nextgen-dast:2.1.1`                 |
| Declared license   | NOASSERTION (no LICENSE file in the source tree)                 |
| Document namespace | `https://github.com/websecusa/nextgen-dast/sbom/2.1.1-<uuid>` |

The application's own source code is enumerated in the SBOM as a
single root component (`pkg:generic/nextgen-dast@2.1.1`); every other
entry is something we either install from a registry (apt, PyPI, npm),
download as a binary from upstream, or vendor into the repo.

---

## Direct dependencies (Dockerfile-declared)

These are the components explicitly listed in `Dockerfile` — the ones
a maintainer chose to install. Everything else in the SBOM is a
transitive dependency pulled in by one of these.

### Python wheels (pip)

| Package           | Version     | License                | Purpose                                                  |
| ----------------- | ----------- | ---------------------- | -------------------------------------------------------- |
| `mitmproxy`       | 11.1.3      | MIT                    | Intercept-proxy engine.                                  |
| `wapiti3`         | 3.2.4       | GPL-2.0-only           | Web app vulnerability scanner.                           |
| `fastapi`         | 0.115.6     | MIT                    | HTTP framework for the orchestrator API.                 |
| `uvicorn[standard]` | 0.32.1   | BSD-3-Clause           | ASGI server.                                             |
| `jinja2`          | 3.1.4       | BSD-3-Clause           | HTML templating.                                         |
| `python-multipart` | 0.0.18     | Apache-2.0             | `multipart/form-data` parsing for file uploads.          |
| `psutil`          | 6.1.0       | BSD-3-Clause           | Process introspection (proxy lifecycle).                 |
| `PyMySQL`         | 1.1.1       | MIT                    | MariaDB driver (pure Python).                            |
| `bcrypt`          | 4.2.0       | Apache-2.0             | Local-account password hashing.                          |
| `weasyprint`      | 62.3        | BSD-3-Clause           | HTML→PDF report rendering.                               |
| `pydyf`           | 0.10.0      | BSD-3-Clause           | PDF primitives used by WeasyPrint.                       |
| `pypdf`           | 5.1.0       | BSD-3-Clause           | PDF inspection / merging.                                |
| `croniter`        | 3.0.3       | MIT                    | Schedule next-run computation.                           |
| `markdown`        | 3.7         | BSD-3-Clause           | Markdown→HTML for finding bodies.                        |
| `python3-saml`    | 1.16.0      | MIT                    | SAML 2.0 SP toolkit (SSO).                               |
| `segno`           | 1.6.1       | BSD-3-Clause           | TOTP enrollment QR rendering.                            |

### npm globals

| Package | Version | License      | Purpose                                                  |
| ------- | ------- | ------------ | -------------------------------------------------------- |
| `retire` | 5.2.5  | Apache-2.0   | retire.js client-side JS vulnerability check.            |
| `yarn`  | 1.22.22 | BSD-2-Clause | `yarn audit` for SCA on captured Yarn lockfiles.         |
| `pnpm`  | 9.15.0  | MIT          | `pnpm audit` for SCA on captured pnpm lockfiles.         |

### Tool binaries (downloaded at image build)

| Tool          | Version              | License        | Source                                            |
| ------------- | -------------------- | -------------- | ------------------------------------------------- |
| `nuclei`      | 3.4.10               | MIT            | github.com/projectdiscovery/nuclei                |
| `dalfox`      | 2.11.0               | MIT            | github.com/hahwul/dalfox                          |
| `ffuf`        | 2.1.0                | MIT            | github.com/ffuf/ffuf                              |
| `osv-scanner` | 1.9.2                | Apache-2.0     | github.com/google/osv-scanner                     |
| `nikto`       | 2.6.0+git.d3a3592    | GPL-2.0-only   | github.com/sullo/nikto                            |
| `testssl.sh`  | 3.3dev+git.0e59b98   | GPL-2.0-only   | github.com/drwetter/testssl.sh                    |

`sqlmap` is also part of the scanner suite but is installed via apt
(`sqlmap` package, GPL-2.0-only) so it appears under the Debian
section of the JSON manifests.

### Vendored data (committed or fetched at build)

| Asset                          | Version            | License    | Purpose                                                  |
| ------------------------------ | ------------------ | ---------- | -------------------------------------------------------- |
| `swagger-ui-dist`              | 5.17.14            | Apache-2.0 | API playground at `/api/v1/docs`.                        |
| `retire.js-jsrepository`       | master+2026-05-08  | Apache-2.0 | Offline retire.js signature DB.                          |
| `nuclei-templates`             | main+git.f173f51   | MIT        | Offline template catalog.                                |
| `SecLists-Web-Content-common`  | 2025-06-15         | MIT        | `ffuf` content-discovery wordlist.                       |

### Container images

| Image                | Tag         | License      | Role                                                |
| -------------------- | ----------- | ------------ | --------------------------------------------------- |
| `python`             | `3.12-slim` | PSF-2.0      | Application image base (Dockerfile FROM).           |
| `mariadb`            | `11`        | GPL-2.0-only | Database backend (compose service).                 |

---

## CycloneDX 1.5

[**`sbom.cdx.json`**](./sbom.cdx.json) (CycloneDX BOM v1.5, JSON
encoding) — 802 components.

CycloneDX is the OWASP-stewarded BOM standard most widely consumed by
OSS vulnerability scanners. Every component carries a
[Package URL](https://github.com/package-url/purl-spec) (`purl`)
identifier so downstream tools can correlate findings against
ecosystem advisory feeds (OSV, NVD, GHSA, …).

### Document shape

```jsonc
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:<deterministic UUIDv5 of repo URL + version + date>",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-09T00:00:00Z",
    "tools":      [ { "vendor": "nextgen-dast maintainers", "name": "sbom_gen.py", "version": "1.0" } ],
    "authors":    [ { "name": "Tim Rice", "email": "tim.j.rice@hackrange.com" } ],
    "supplier":   { "name": "Tim Rice <tim.j.rice@hackrange.com>" },
    "component":  { /* the application itself, with vcs + distribution refs */ }
  },
  "components": [ /* one entry per dep, see samples below */ ]
}
```

### Sample component entries

Direct PyPI dependency (FastAPI):

```json
{
  "type": "library",
  "bom-ref": "pkg:pypi/fastapi@0.115.6",
  "name": "fastapi",
  "version": "0.115.6",
  "purl": "pkg:pypi/fastapi@0.115.6",
  "licenses": [{ "expression": "MIT" }]
}
```

Tool binary (nuclei):

```json
{
  "type": "application",
  "bom-ref": "pkg:github/projectdiscovery/nuclei@v3.4.10",
  "name": "nuclei",
  "version": "3.4.10",
  "purl": "pkg:github/projectdiscovery/nuclei@v3.4.10",
  "licenses": [{ "expression": "MIT" }],
  "supplier": { "name": "ProjectDiscovery" },
  "externalReferences": [
    { "type": "distribution",
      "url":  "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_amd64.zip" }
  ]
}
```

Container base image:

```json
{
  "type": "container",
  "bom-ref": "pkg:docker/python@3.12-slim",
  "name": "python",
  "version": "3.12-slim",
  "purl": "pkg:docker/python@3.12-slim",
  "licenses": [{ "expression": "PSF-2.0" }],
  "supplier": { "name": "Python Software Foundation" },
  "externalReferences": [
    { "type": "distribution", "url": "docker.io/library/python:3.12-slim" }
  ],
  "description": "Dockerfile FROM (application image base)"
}
```

### Validating

```bash
# Schema validation
pip install cyclonedx-bom-validator
cyclonedx-validator sbom.cdx.json

# Or with the official Java-based validator
docker run --rm -v "$PWD:/work" cyclonedx/cyclonedx-cli \
    validate --input-file /work/sbom.cdx.json
```

### Consuming

```bash
# Vulnerability scan via OSV
osv-scanner --sbom=sbom.cdx.json

# Or load into Dependency-Track
curl -X POST -H "X-Api-Key: $DT_KEY" \
     -F "bom=@sbom.cdx.json" \
     -F "projectName=nextgen-dast" -F "projectVersion=2.1.1" \
     "$DT_URL/api/v1/bom"
```

---

## SPDX 2.3

[**`sbom.spdx.json`**](./sbom.spdx.json) (SPDX 2.3, JSON encoding) —
803 packages, 803 relationships.

SPDX is the ISO/IEC 5962:2021 standard for SBOMs and the format
required by NTIA "minimum-elements" mandates and most
US Federal procurement (Executive Order 14028) compliance pipelines.
Every package carries the same `purl` PackageManager external
reference as the CycloneDX entry, so downstream tools can dedupe
across the two formats.

### Document shape

```jsonc
{
  "spdxVersion":  "SPDX-2.3",
  "dataLicense":  "CC0-1.0",
  "SPDXID":       "SPDXRef-DOCUMENT",
  "name":         "nextgen-dast-2.1.1",
  "documentNamespace": "https://github.com/websecusa/nextgen-dast/sbom/2.1.1-<uuid>",
  "creationInfo": {
    "created":  "2026-05-09T00:00:00Z",
    "creators": [
      "Person: Tim Rice (tim.j.rice@hackrange.com)",
      "Tool: sbom_gen.py-1.0"
    ],
    "licenseListVersion": "3.24"
  },
  "packages":      [ /* root + every dep, see samples below */ ],
  "relationships": [ /* SPDXRef-DOCUMENT DESCRIBES root, root DEPENDS_ON each dep */ ]
}
```

### Sample package entries

Root package (the application itself):

```json
{
  "SPDXID": "SPDXRef-Pkg-nextgen-dast-2.1.1",
  "name": "nextgen-dast",
  "versionInfo": "2.1.1",
  "downloadLocation": "https://github.com/websecusa/nextgen-dast.git",
  "filesAnalyzed": false,
  "licenseConcluded": "NOASSERTION",
  "licenseDeclared":  "NOASSERTION",
  "copyrightText":    "Copyright (c) 2026 Tim Rice",
  "supplier": "Person: Tim Rice (tim.j.rice@hackrange.com)",
  "externalRefs": [
    { "referenceCategory": "PACKAGE-MANAGER",
      "referenceType":     "purl",
      "referenceLocator":  "pkg:generic/nextgen-dast@2.1.1" }
  ]
}
```

Direct PyPI dependency (FastAPI):

```json
{
  "SPDXID": "SPDXRef-PyPI-fastapi-0.115.6",
  "name": "fastapi",
  "versionInfo": "0.115.6",
  "downloadLocation": "NOASSERTION",
  "filesAnalyzed": false,
  "licenseConcluded": "MIT",
  "licenseDeclared":  "MIT",
  "copyrightText":    "NOASSERTION",
  "supplier": "NOASSERTION",
  "externalRefs": [
    { "referenceCategory": "PACKAGE-MANAGER",
      "referenceType":     "purl",
      "referenceLocator":  "pkg:pypi/fastapi@0.115.6" }
  ]
}
```

Relationships (one per dep, root → child):

```json
[
  { "spdxElementId": "SPDXRef-DOCUMENT",
    "relationshipType": "DESCRIBES",
    "relatedSpdxElement": "SPDXRef-Pkg-nextgen-dast-2.1.1" },
  { "spdxElementId": "SPDXRef-Pkg-nextgen-dast-2.1.1",
    "relationshipType": "DEPENDS_ON",
    "relatedSpdxElement": "SPDXRef-PyPI-fastapi-0.115.6" }
]
```

### Validating

```bash
# Reference validator from the SPDX project
pip install spdx-tools
pyspdxtools --infile sbom.spdx.json

# Or the online tool: https://tools.spdx.org/app/validate/
```

### Consuming

```bash
# OSV-Scanner reads SPDX directly
osv-scanner --sbom=sbom.spdx.json

# FOSSology, ScanCode, Anchore, GitHub dependency-graph, and
# the NTIA SBOM portal all accept the same JSON.
```

---

## How this SBOM was generated

The SBOM is produced by a one-off Python script that captures
`pip freeze`, `dpkg-query`, and `npm ls -g` from a freshly-built
2.1.1 container, then merges in the manually-tracked tool binaries,
vendored data, and base images that none of those manifests cover.

To regenerate after changing the Dockerfile or pinned versions:

1. Build and start the image so the in-container manifests reflect
   the new state:
   ```bash
   docker build -t dockerregistry.fairtprm.com/nextgen-dast:2.1.1 .
   ./pentest.sh up -d
   ```
2. Capture inputs:
   ```bash
   docker exec nextgen-dast pip freeze            > /tmp/sbom_pip.txt
   docker exec nextgen-dast dpkg-query -W -f \
       '${Package}\t${Version}\t${Architecture}\n' > /tmp/sbom_deb.txt
   ```
3. Re-run the generator (kept out of git as a transient helper) and
   commit the regenerated `sbom.cdx.json` / `sbom.spdx.json` /
   updated `SBOM.md` together.

---

## Refresh policy

Refresh this SBOM on any of:

- A version bump of the application (the `2.1.1` in the document
  metadata is load-bearing for compliance reporting).
- A change to `Dockerfile` that adds, removes, or repins a package.
- A refresh of any vendored data file (Swagger UI, retire.js DB,
  nuclei-templates, SecLists wordlist).

Because the application image is rebuilt and re-pushed under the
**same** `2.1.1` tag (per the project's no-bump-without-permission
rule), the `metadata.timestamp` / `creationInfo.created` field of the
SBOM is the most reliable signal of which build of `2.1.1` the file
describes.

---

## Provenance and limitations

- The Debian package list is the full installed set inside the
  image, including transitive dependencies pulled in by apt; that is
  why the count is large (669 entries). A targeted compliance review
  should focus on the Dockerfile-declared subset called out under
  **Direct dependencies** above.
- License fields for Debian packages are recorded as `NOASSERTION`
  in both manifests: `dpkg` does not store an SPDX identifier, and
  the per-package `copyright` files would need separate parsing.
  Run a dedicated scanner (Syft, ScanCode) against the live image
  for a license-accurate Debian sub-SBOM.
- License fields for PyPI packages are taken from a curated map in
  the generator script, validated against each project's PyPI page.
  Dual-licensed packages are recorded with an SPDX `OR` expression.
- The SBOM does not enumerate every individual file shipped inside
  the image; it operates at package granularity, which is what
  CycloneDX, SPDX, and downstream scanners expect.
