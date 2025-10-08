# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        perl \
        libnet-ssleay-perl \
        libio-socket-ssl-perl \
        libjson-perl \
        libtimedate-perl \
        libxml-writer-perl \
        libtext-csv-perl \
        libwww-perl \
        libhtml-parser-perl \
        ca-certificates \
        curl \
        git \
        bind9-dnsutils \
        bsdmainutils \
        dnsutils \
        procps \
        openssl \
        sqlmap \
        unzip \
        tini \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        fonts-liberation \
        fonts-dejavu \
        fontconfig \
        # mariadb-client provides mariadb-dump and the mariadb shell. The
        # Settings → Database backup / restore feature shells out to both;
        # without this package the orchestrator can dump rows via pymysql
        # but cannot produce a faithful schema-aware backup.
        mariadb-client \
        # nmap is used by the testssl-style cipher-order reproduction to
        # confirm server preference per protocol (ssl-enum-ciphers).
        nmap \
    && rm -rf /var/lib/apt/lists/*

# Nikto is a Perl script — install from upstream (not in Debian trixie main)
RUN git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# testssl.sh — TLS / cipher / cert analyzer
RUN git clone --depth=1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# nuclei — template-based vulnerability scanner (Go binary)
ARG NUCLEI_VERSION=3.4.10
RUN ARCH=$(dpkg --print-architecture | sed 's/x86_64/amd64/') \
    && curl -sSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git \
        /root/nuclei-templates

# dalfox — fast XSS scanner (Go binary)
ARG DALFOX_VERSION=2.11.0
RUN ARCH=$(dpkg --print-architecture | sed 's/x86_64/amd64/') \
    && curl -sSL -o /tmp/dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_${DALFOX_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm /tmp/dalfox.tar.gz

# Node.js — runtime for retire.js (and the npm/yarn/pnpm audit CLIs invoked
# by the SCA stage when an exposed lockfile is retrieved). The Debian
# `nodejs` package in trixie is current enough; we only use it for the
# audit + retire.js binaries, never as a server runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/* \
    && npm config set update-notifier false \
    && npm install -g --no-fund --no-audit \
        retire@5.2.5 \
        yarn@1.22.22 \
        pnpm@9.15.0

# retire.js refreshes its signature DB at runtime, but we bake the
# upstream `jsrepository.json` and a copy of the OSV-Scanner so the
# image works fully offline on first boot. scripts/update_scanners.py
# refreshes both periodically once the container has network access.
RUN mkdir -p /opt/sca/retire \
    && curl -sSL -o /opt/sca/retire/jsrepository.json \
        "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"

# OSV-Scanner — multi-ecosystem SCA from Google. One binary covers
# npm, pypi, gem, maven, go, composer, cargo, nuget. We use it both
# for online lookups (osv.dev) and against the offline OSV DB that
# scripts/update_scanners.py refreshes into /data/sca/osv-db/.
ARG OSV_SCANNER_VERSION=1.9.2
RUN ARCH=$(dpkg --print-architecture | sed 's/x86_64/amd64/') \
    && curl -sSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${ARCH}" \
    && chmod +x /usr/local/bin/osv-scanner

# ffuf — fast web fuzzer (Go binary). Used for content discovery
# (paths) in the thorough/premium profiles. The wordlist is vendored
# at toolkit/wordlists/web-content.txt (see toolkit/wordlists/SOURCES.md
# for provenance) and copied into /opt/wordlists/ below so a fully
# air-gapped rebuild from this checkout works without network access
# beyond the ffuf binary itself.
ARG FFUF_VERSION=2.1.0
RUN ARCH=$(dpkg --print-architecture | sed 's/x86_64/amd64/') \
    && curl -sSL -o /tmp/ffuf.tar.gz \
        "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm /tmp/ffuf.tar.gz \
    && mkdir -p /opt/wordlists
COPY toolkit/wordlists/web-content.txt /opt/wordlists/web-content.txt

RUN pip install \
        "mitmproxy==11.1.3" \
        "wapiti3==3.2.4" \
        "fastapi==0.115.6" \
        "uvicorn[standard]==0.32.1" \
        "jinja2==3.1.4" \
        "python-multipart==0.0.18" \
        "psutil==6.1.0" \
        "PyMySQL==1.1.1" \
        "bcrypt==4.2.0" \
        "weasyprint==62.3" \
        "pydyf==0.10.0" \
        "pypdf==5.1.0" \
        "croniter==3.0.3"

# Swagger UI assets, vendored into the image so the API playground at
# /api/v1/docs works on hosts that have no outbound internet access (or
# whose CSP blocks third-party CDNs). We pin the version so the bundle
# layer caches and the page behaves identically across rebuilds.
ARG SWAGGER_UI_VERSION=5.17.14
RUN mkdir -p /opt/swagger-ui \
    && curl -sSL -o /opt/swagger-ui/swagger-ui.css \
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@${SWAGGER_UI_VERSION}/swagger-ui.css" \
    && curl -sSL -o /opt/swagger-ui/swagger-ui-bundle.js \
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@${SWAGGER_UI_VERSION}/swagger-ui-bundle.js"

WORKDIR /app
COPY app/ /app/

# Place the vendored Swagger UI bundle into the static-assets directory
# served by uvicorn (mounted at /static in server.py). One layer, copied
# late so a swagger-ui version bump doesn't bust the python deps cache.
RUN mkdir -p /app/static/swagger-ui \
    && cp /opt/swagger-ui/swagger-ui.css /app/static/swagger-ui/swagger-ui.css \
    && cp /opt/swagger-ui/swagger-ui-bundle.js /app/static/swagger-ui/swagger-ui-bundle.js
# scripts/, toolkit/, and db/ used to be host-mounted at runtime. Bake them
# into the image so a registry-image deployment works without a working copy
# of the source on disk.
COPY scripts/ /app/scripts/
COPY toolkit/ /app/toolkit/
COPY db/ /app/db/
# enhanced_testing/ ships proactive probes that run during the `premium`
# profile. Shares the toolkit/lib via its own lib/__init__.py shim so
# probes have a single import path.
COPY enhanced_testing/ /app/enhanced_testing/

RUN mkdir -p /data/flows /data/logs /data/scans \
             /data/sca /data/sca/osv-db /data/sca/manifests \
             /data/scanners

EXPOSE 8888 9443

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", "8888"]
