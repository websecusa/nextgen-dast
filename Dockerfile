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
        "pypdf==5.1.0"

WORKDIR /app
COPY app/ /app/
# scripts/, toolkit/, and db/ used to be host-mounted at runtime. Bake them
# into the image so a registry-image deployment works without a working copy
# of the source on disk.
COPY scripts/ /app/scripts/
COPY toolkit/ /app/toolkit/
COPY db/ /app/db/

RUN mkdir -p /data/flows /data/logs /data/scans

EXPOSE 8888 9443

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", "8888"]
