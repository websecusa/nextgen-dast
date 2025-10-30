# Wordlist sources

Vendored wordlists are committed to the repository so a registry-image
build (or a fully air-gapped rebuild) does not require network access.
Refresh manually when the upstream catalog meaningfully changes.

## web-content.txt

- Source: https://github.com/danielmiessler/SecLists
- Path:   `Discovery/Web-Content/common.txt`
- License: MIT (see SecLists repository)
- Used by: `ffuf` content-discovery pass in `scripts/orchestrator.py`
- Last refreshed: 2025-06-15

To refresh:

```
curl -sSL -o toolkit/wordlists/web-content.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
```

Then rebuild + retag the 2.1.1 image and commit both files together.
