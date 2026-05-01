# nextgen-dast

_Author: Tim Rice <tim.j.rice@hackrange.com>_

Authenticated DAST orchestrator with a built-in HTTP intercept proxy, a
multi-tool scanner pipeline (wapiti, nuclei, nikto, testssl, sqlmap,
dalfox), LLM-assisted analysis, finding enrichment with ticket-export, and
a high-fidelity validation toolkit. Ships as a Docker image
(`dockerregistry.fairtprm.com/nextgen-dast:2.1.1`) with a single
`docker-compose.yml` for the application + MariaDB.

This README walks you through a fresh-machine install end-to-end. If
something doesn't work, jump to **Troubleshooting** at the bottom.

---

## TL;DR — fast path

On a fresh Ubuntu / Debian / Kali / RHEL / Oracle Linux box:

```bash
# 1. Make the deploy directory and own it as your user.
sudo mkdir -p /data/pentest
sudo chown "$USER":"$USER" /data/pentest

# 2. Clone the source tree directly into the deploy directory.
#    This brings in setup.sh, docker-compose.yml, the Dockerfile, and
#    everything else listed under "Files you need" below.
git clone https://github.com/websecusa/nextgen-dast.git

# 3. Run the bootstrap helper.
cd /data/pentest
sudo ./setup.sh
```

That's it. The application image at
`dockerregistry.fairtprm.com/nextgen-dast:2.1.1` is **publicly pullable**
— no `docker login` and no registry credentials required to install or
upgrade. (Login is only needed if you're pushing new images to the
registry, which is the maintainer's job, not yours.)

`setup.sh` will:
1. Install Docker Engine + Compose plugin if they aren't present.
2. Pull `nextgen-dast:2.1.1` from the registry.
3. Generate a random `.env_<hex>` file with strong secrets (see **Secrets** below).
4. Bring up MariaDB, wait for it to be healthy.
5. Apply the schema and seed an `admin` user.
6. Print the path to the freshly generated admin password.

### Secrets

setup.sh **never uses default or shared passwords**. Every install gets
its own:

| Secret | How it's generated | Where it lives |
|---|---|---|
| Env-file suffix | `openssl rand -hex 8` (e.g. `.env_a1b2c3d4e5f6g7h8`) | filename in `/data/pentest/` |
| MariaDB root password | `openssl rand -hex 24` (192 bits) | env file, `chmod 600` |
| MariaDB app-user password | `openssl rand -hex 24` (192 bits) | env file, `chmod 600` |
| Session cookie key (`APP_SECRET`) | `openssl rand -hex 32` (256 bits) | env file, `chmod 600` |
| Admin user password | `secrets.choice` over a 24-char alphabet (CSPRNG) | `data/.sensitive_secrets_info_<suffix>`, `chmod 600` |

The env-file name itself is randomised because plain `.env` is the first
filename automated leak-scrapers look for. Setup refuses to run if it
finds a plain `.env` file or detects placeholder/weak values from
`.env.example` — fail loud, never silent.

Then add an nginx (or Caddy) TLS-terminating reverse proxy in front of
`127.0.0.1:8888` (see **TLS / reverse proxy** below) and you're live.

---

## What you actually need

The deployment lives in **`/data/pentest`** on the host. After this README
is done, that directory must contain at least:

```
/data/pentest/
├── docker-compose.yml      # the stack definition (registry image)
├── setup.sh                # the first-run helper script
├── db/
│   └── schema.sql          # MariaDB seeds the database from this on first start
└── data/                   # created automatically; persistent runtime state
```

Optional but recommended (let you re-build the image locally if your
network later loses access to the registry):

```
├── Dockerfile
├── app/                    # Python source
├── scripts/                # orchestrator + reset
└── toolkit/                # validation probes
```

You don't need MySQL or MariaDB installed on the host. The MariaDB instance
the application uses is bundled inside the compose stack and stores its
data under `/data/pentest/data/mariadb/`.

---

## Hardware / OS requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB (LLM analysis benefits from more) |
| Disk | 30 GB | 100 GB+ (scan artifacts can be GB-scale per assessment) |
| OS | Ubuntu 22.04 / Debian 12 / Kali rolling / RHEL 9 / Oracle Linux 9 | Ubuntu 24.04 LTS |
| Network | Outbound to `dockerregistry.fairtprm.com` and Docker Hub | + outbound to your scan targets |

x86_64 and arm64 builds are both produced by the registry image.

---

## Step-by-step from a fresh box

### 1. Get the files onto the host

The repository contains everything you need — `setup.sh`, the
`docker-compose.yml`, the schema, plus the source if you ever want to
build the image locally. Clone it into `/data/pentest`:

```bash
sudo mkdir -p /data/pentest
sudo chown "$USER":"$USER" /data/pentest
git clone https://github.com/websecusa/nextgen-dast.git /data/pentest
```

(Alternative if a `git` client isn't available — `curl` a release
tarball and unpack it:

```bash
sudo mkdir -p /data/pentest
sudo curl -fsSL -o /tmp/nextgen-dast.tgz \
    https://github.com/websecusa/nextgen-dast.git/archive/2.1.1.tar.gz
sudo tar -xzf /tmp/nextgen-dast.tgz -C /data/pentest --strip-components=1
sudo chown -R "$USER":"$USER" /data/pentest
```
)

Verify:

```bash
ls /data/pentest
# expect: app  db  docker-compose.yml  Dockerfile  README.md
#         scripts  setup.sh  toolkit  pentest.sh
```

### 2. (Optional) verify the image is reachable

The application image is **publicly pullable** — no login required —
but it's worth confirming connectivity before you run setup, especially
if you're behind a corporate firewall or proxy:

```bash
docker pull dockerregistry.fairtprm.com/nextgen-dast:2.1.1
```

A successful pull means you're ready. If it fails, see
**Troubleshooting → "Cannot reach the registry"** below.

> If for some reason you can't reach the registry at all, you can build
> the image locally from the source you just cloned. Pass `--build` to
> `setup.sh` in step 4 instead and skip this step.

### 3. (Optional) decide your public URL

The application listens on `127.0.0.1:8888` inside the container. You'll
front it with a TLS-terminating reverse proxy at a stable public URL.
If you already know what URL you want, export it before running setup so
the env file gets the right value out of the gate:

```bash
export APP_URL="https://pentest.example.com/"   # mind the trailing slash
```

If you don't set it, `setup.sh` defaults to `https://localhost/`,
which you can change later by editing the generated `.env_<hex>` file.

### 4. Run setup.sh

```bash
cd /data/pentest
sudo ./setup.sh
```

The script is **idempotent** — safe to re-run if something fails halfway.
Useful flags:

* `sudo ./setup.sh --build` — build the image locally instead of pulling.
  Use when you don't have registry access. Needs all of `app/`,
  `scripts/`, `toolkit/`, `db/`, and `Dockerfile` on disk.
* `sudo ./setup.sh --no-install` — skip the Docker installation step.
  Use when Docker is already installed and you're just running the
  bootstrap part.
* `sudo ./setup.sh --help` — print the comment block at the top of the
  script.

When it finishes, look for output like:

```
Admin credentials are in:
    /data/pentest/data/.sensitive_secrets_info_a1b2c3d4
```

`cat` that file (or use `sudo cat` if you didn't run setup as a user with
read access to `/data/pentest/data/`) to get the admin username and
password.

### 5. Put a reverse proxy in front

The app refuses to set the session cookie over plain HTTP (the cookie has
the `Secure` flag), so you **must** front it with TLS. Two common options:

#### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name pentest.example.com;

    ssl_certificate     /etc/letsencrypt/live/pentest.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pentest.example.com/privkey.pem;

    # The application is mounted at the root path; pass everything through.
    location / {
        proxy_pass http://127.0.0.1:8888/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
    }
}
```

Then `sudo nginx -t && sudo systemctl reload nginx`.

#### Caddy

```caddy
pentest.example.com {
    reverse_proxy 127.0.0.1:8888
}
```

Caddy auto-issues TLS — no certbot needed.

### 6. Log in

Visit `https://pentest.example.com/` and log in with `admin` and the
password from the secrets file. Change the password under your user menu
right after first login.

---

## Capturing authenticated sessions with the built-in proxy

This is the workflow for assessing an application behind SAML / SSO (Okta,
Azure AD, Google, ADFS, Ping, etc.). The end goal is a captured session
cookie that the scanners can replay against authenticated endpoints.

The application bundles **mitmproxy** (specifically `mitmdump`) as a
**reverse proxy**: clients don't need to change their browser network
settings. They just point their browser at the proxy URL and the proxy
forwards requests to the real target with the right Host header.

> The two confusing words in this paragraph:
> - **Reverse proxy:** the proxy *pretends to be the target*. You browse to
>   the proxy URL and it forwards transparently. No browser settings needed.
> - **Forward proxy:** the proxy is configured *in your browser's network
>   settings*, and it relays whatever URL you type. We support this too,
>   covered as Option B at the bottom of this section.
>
> **You almost always want reverse proxy mode.** It's simpler, doesn't
> affect non-target traffic, and works with corporate machines that lock
> down browser proxy settings.

### Vocabulary cheat-sheet (mentally substitute as you read)

| In this guide | What it means in your environment |
|---|---|
| **Target / SP** | The web application you're assessing (e.g. `target.example.com`) |
| **IdP** | The identity provider doing the SAML login (e.g. `login.okta.com`) |
| **Proxy host** | The machine running this application (could be `localhost` or a remote IP) |
| **Listener port** | What you set on the `/proxy` page; default `9443` |

---

### Option A — Reverse proxy (recommended for SAML)

This is the default mode and what the rest of the guide assumes. End state:
your browser hits `https://target.example.com/`, traffic transparently
flows through `mitmdump` on the proxy host, and every request/response is
logged. SAML works because the IdP redirect lands on `target.example.com`
which (thanks to one `/etc/hosts` line) resolves to the proxy.

#### 1. Configure the proxy in this app

In your browser, open the application UI: `https://<proxy-host>/proxy`.
You'll see the **Intercept proxy** page. Fill in the form:

| Field | Value to enter | Why |
|---|---|---|
| **Listen host** | `127.0.0.1` | Listen on loopback so only this machine reaches it. Use `0.0.0.0` only if you need to expose the proxy on a LAN. |
| **Listen port** | `9443` (default) | The port your browser will connect to. Pick anything 1024–65535 if 9443 is taken. |
| **Upstream URL** | `https://target.example.com` | The real application you want to test. **Use the public URL exactly as the SP knows itself**, including the scheme. |
| **Upstream Host header** | `target.example.com` | Rewrites the `Host:` header before the request reaches the SP. Most SAML SPs validate this — set it to the same hostname as the upstream. |
| **Skip TLS verification on upstream** | ✓ checked | Lets the proxy trust self-signed / staging upstream certs. Leave unchecked if the upstream has a real CA-issued cert and you want the proxy to verify it. |

Click **Save**, then **Start**. The "Status" line should turn green and
say `started pid <number>`.

#### 2. Install the mitmproxy CA certificate (one-time per client device)

Without this, your browser will scream "Not Secure" at every page.
mitmproxy generates its own CA on first run. You need to install that CA
as a trusted root on every device that will browse through the proxy.

**Get the certificate file** — on the proxy host:

```bash
docker cp nextgen-dast:/root/.mitmproxy/mitmproxy-ca-cert.pem ./mitm-ca.pem
```

Now copy `mitm-ca.pem` to whatever device you'll be browsing from (USB
stick, scp, secure file share — not email).

**Install it** — pick the OS / browser combination matching your client:

<details><summary><strong>Windows (Chrome / Edge)</strong></summary>

1. Double-click `mitm-ca.pem`. Windows opens the **Certificate** dialog.
2. Click **Install Certificate…**
3. Choose **Current User**, click **Next**.
4. Choose **Place all certificates in the following store**, click **Browse**.
5. Pick **Trusted Root Certification Authorities**, click **OK**, then **Next** → **Finish**.
6. A scary "are you sure?" dialog appears — click **Yes**.
7. Restart Chrome / Edge.
</details>

<details><summary><strong>macOS (Safari / Chrome)</strong></summary>

1. Double-click `mitm-ca.pem`. **Keychain Access** opens.
2. Choose **System** keychain (not Login), click **Add**. Type your admin password.
3. In Keychain Access, find `mitmproxy` in the System keychain. Double-click it.
4. Expand **Trust** → set **When using this certificate** to **Always Trust**. Close the window, type your password again to confirm.
5. Restart Safari / Chrome.
</details>

<details><summary><strong>Linux (Chrome / Firefox)</strong></summary>

System-wide trust:
```bash
sudo cp mitm-ca.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

Firefox uses its own cert store and ignores the system one. In Firefox:
**Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → mitm-ca.pem**, tick **Trust this CA to identify websites**.
</details>

<details><summary><strong>Firefox on any OS</strong></summary>

Firefox always uses its own cert store. Same steps as the Linux/Firefox
block above:
**Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**.
</details>

To verify the install worked, open a new tab and visit `https://mitm.it`
(special URL the proxy serves). It should load **without** a TLS warning.

#### 3. Make `target.example.com` resolve to the proxy

This is the trick that lets SAML work. We need `target.example.com` —
the URL the SAML SP knows itself by — to resolve to the proxy host
**only on the client device doing the assessment**.

Edit `/etc/hosts` (Linux/macOS) or
`C:\Windows\System32\drivers\etc\hosts` (Windows, run editor as admin):

```
# Routes the target through the proxy. Remove this line when finished.
<proxy-host-IP>   target.example.com
```

Replace `<proxy-host-IP>` with the IP of the machine running this
application. If the proxy is on the same machine as the browser, use
`127.0.0.1`.

> **Do not redirect the IdP** (e.g. `login.okta.com`). Only the target
> hostname goes in `/etc/hosts`. The IdP needs to resolve normally so the
> SAML flow can complete.

#### 4. Browse and authenticate

Open your browser and go to:

```
https://target.example.com:9443/
```

(Port 9443 is the listener port from step 1. If your proxy listens on
the default 443, omit the `:9443` and you can use a plain
`https://target.example.com/`.)

You should see the **target application's login page**, served through
the proxy. Click whatever button initiates SAML login — typically
**"Sign in with SSO"** or **"Login with Okta"**. The flow goes:

1. Your browser → proxy → target → SAML AuthnRequest → redirect to IdP
2. Browser follows the redirect to the **real** IdP (this leaves the proxy)
3. You enter your IdP credentials + MFA at the IdP
4. IdP POSTs the SAML response back to the target's ACS URL
5. Target consumes the response, **sets a session cookie**, redirects you to the post-login landing page
6. **Steps 1, 4, 5, 6+ all flow through the proxy** — the cookie is captured.

#### 5. Save the captured session as an auth profile

Now that you're logged in via the proxy, every authenticated request
your browser makes is being recorded. Click around the application a
bit so a few authenticated flows land in the log.

In the application UI, open **Flows** (`/flows`). You'll see a list
of every request that went through the proxy. Find one with a
`Cookie:` header set (any post-login request).

Open **Auth profiles** (`/auth`). Use the **Capture from flow**
form:

| Field | Value |
|---|---|
| **Flow ID** | The ID of the authenticated flow you found above |
| **Profile name** | Something memorable like `target-saml-prod` |
| **Host filter** | `target.example.com` (so the cookies are only sent to this host) |

Click **Capture**. The session cookie + any authenticated request headers
are saved as an auth profile under that name.

#### 6. Run an authenticated scan

Go to **Assessments** (`/assess`) or **Scans** (`/scan`). When
you start a scan, pick the auth profile you just saved. The scanner will
inherit the session cookies and run as the authenticated user.

#### 7. Clean up when finished

- Remove the line you added to `/etc/hosts` so `target.example.com`
  resolves normally again.
- On the proxy page, click **Stop** to shut down `mitmdump`.
- The mitmproxy CA stays installed on your client unless you remove it
  manually (recommended on shared / public devices).

---

### Option B — Forward proxy (browser network settings)

Use this when you can't (or don't want to) modify `/etc/hosts`. The
browser sends every request through the proxy regardless of the URL.

**This is not currently a built-in mode of the application** — the
in-app proxy is hardcoded to reverse mode. To use forward mode, run
`mitmdump` directly on the proxy host alongside the application:

```bash
docker exec nextgen-dast mitmdump --mode regular \
    --listen-host 0.0.0.0 --listen-port 8080 \
    --set ssl_insecure=true \
    --set flow_log_path=/data/logs/flows.jsonl \
    -s /app/proxy_addon.py
```

(Run that on the proxy host — it spins up a forward proxy on port 8080
inside the same container, sharing the same flow-log so the
application's UI still lists the captured flows.)

In your browser, set **HTTP/HTTPS proxy**:

| Browser | Where to set the proxy |
|---|---|
| **Chrome / Edge / Brave** (Windows) | Use system settings: Settings → Network & Internet → Proxy → Manual proxy setup → IP `127.0.0.1` (or proxy host IP), Port `8080`. |
| **Chrome / Edge / Brave** (macOS) | System Settings → Network → (interface) → Details → Proxies → Web Proxy (HTTP) and Secure Web Proxy (HTTPS), both `127.0.0.1:8080`. |
| **Chrome / Edge / Brave** (Linux) | Use system settings or launch with `--proxy-server="http=127.0.0.1:8080;https=127.0.0.1:8080"`. |
| **Firefox** (any OS) | Settings → Network Settings → Manual proxy configuration → HTTP proxy `127.0.0.1`, Port `8080`, ✓ "Also use this proxy for HTTPS". |
| **Safari** | macOS network settings (same as Chrome on macOS — Safari uses the system proxy). |

**Proxy values to enter:**

| Field | Value |
|---|---|
| **Type** | HTTP proxy (used for both HTTP and HTTPS — no separate SOCKS, no PAC) |
| **Host / address** | `127.0.0.1` if running in the same machine, otherwise the proxy host's LAN IP |
| **Port** | `8080` (the port you used in the `mitmdump --listen-port` argument above) |
| **Bypass list** | Leave blank, or add `localhost,127.0.0.1` if the browser fights you |

Then install the mitmproxy CA cert (same as Option A step 2) and visit
the target's real URL — `https://target.example.com/` — directly. Every
request is intercepted. SAML works without `/etc/hosts` changes because
the IdP traffic also goes through the proxy.

**When you're done**, set the browser proxy back to **No proxy / System
proxy / Automatic** so non-assessment traffic doesn't get intercepted.

---

### Common SAML pitfalls

| Symptom | Likely cause | Fix |
|---|---|---|
| `https://target.example.com:9443/` shows a TLS warning | mitmproxy CA cert not installed (or not in the right cert store) | Re-do step 2 — note Firefox needs its own import |
| SAML login starts, IdP loads, but the redirect back fails | `/etc/hosts` redirected the IdP too, so the browser couldn't reach the real IdP | Only redirect the SP (target), not the IdP |
| SAML login completes but the SP shows "invalid SAML audience" | Upstream Host header doesn't match what the SP expects | Set "Upstream Host header" to exactly the hostname from the SP's metadata (e.g. `target.example.com`, not `localhost`) |
| Browser hangs at "Connecting to target.example.com…" | `/etc/hosts` line is wrong, or proxy isn't running | Check `proxy_pid()` via `/proxy`; verify with `curl -k https://target.example.com:9443/` from the client |
| SAML works in Chrome but not Firefox | Firefox uses its own cert store and ignores the system one | Re-run the cert install steps inside Firefox specifically |
| Authenticated requests work for ~30 minutes then 401 | SAML session expired; you need to re-capture | Repeat steps 4–5 to capture a fresh cookie |

---

## Day-2 operations

The `pentest.sh` script wraps `docker compose` with the right `--env-file`
flag — saves you from typing it every time. Use it for everything you'd
normally hand to `docker compose`, plus a few extras like `reset` for
admin-password rotation.

### Quick reference

The table below is the canonical cheat sheet — `HELP.txt` in this directory
mirrors the same content for at-a-glance use on the host. Anything not
listed here (e.g. `./pentest.sh top`, `./pentest.sh config`,
`./pentest.sh kill`) is forwarded straight to `docker compose` with the
right `--env-file`, so the full Compose CLI is available without typing
the env-file path each time.

#### First-time bring-up

| What you want | Run this |
|---|---|
| First-time host setup (Docker, sysctls, certs) — only once per host | `sudo ./setup.sh` |
| First-time stack bring-up (generate env file, build, start, seed admin) | `./pentest.sh bootstrap` |

`setup.sh` runs once per host and is the bootstrap helper from the deploy
tarball; `pentest.sh bootstrap` runs once per deployment and is what
actually creates the random `.env_<hex>` file, builds (or pulls) the
image, brings the stack up, waits for MariaDB to be healthy, then runs
the initial `reset` so you have a working admin password.

#### Lifecycle

| What you want | Run this |
|---|---|
| Start the stack | `./pentest.sh up -d` |
| Stop the stack (remove containers, keep data volume) | `./pentest.sh down` |
| Stop services without removing the containers | `./pentest.sh stop` |
| Start previously-stopped containers | `./pentest.sh start` |
| Restart everything | `./pentest.sh restart` (or `./pentest.sh down && ./pentest.sh up -d`) |
| Restart just the app, leave MariaDB alone | `./pentest.sh restart nextgen-dast` |

#### Image management

| What you want | Run this |
|---|---|
| Pull a new image from the registry | `./pentest.sh pull` |
| Pull **and** restart with the new image | `./pentest.sh pull && ./pentest.sh up -d` |
| Build the image locally from `./Dockerfile` | `./pentest.sh build` |
| Rebuild from local source **and** restart | `./pentest.sh build && ./pentest.sh up -d` |
| Force a clean rebuild (no cache) | `./pentest.sh build --no-cache` |

#### Inspection

| What you want | Run this |
|---|---|
| See what's running and the image tag in use | `./pentest.sh ps` |
| Tail app logs (follow) | `./pentest.sh logs -f nextgen-dast` |
| Tail DB logs (follow) | `./pentest.sh logs -f mariadb` |
| Dump the last 200 lines of app logs and exit | `./pentest.sh logs --tail 200 nextgen-dast` |
| Show running container resource usage | `./pentest.sh top` |
| Validate the rendered compose config | `./pentest.sh config` |

#### Shells

| What you want | Run this |
|---|---|
| Bash shell inside the app container | `./pentest.sh exec nextgen-dast bash` |
| MariaDB SQL shell as root (password is in the `.env_<hex>` file) | `./pentest.sh exec mariadb mariadb -uroot -p` |

#### Admin / data

| What you want | Run this |
|---|---|
| Rotate admin password and re-seed (keeps assessments, findings, scans) | `./pentest.sh reset` |
| Change admin password to a known value | `./pentest.sh reset --admin-password 'pass'` |
| Wipe every application table **and** rotate admin (destructive!) | `./pentest.sh reset-full` |

`./pentest.sh reset` writes a new secrets file and rotates the admin
password but **keeps all assessments, findings, scans, and reports**.
`./pentest.sh reset-full` truncates every application table on top of that
— use it only when you genuinely want to start from an empty database.

### Upgrading to a newer image

When a new tag (e.g. `2.1.2`) is published:

```bash
# Edit docker-compose.yml — change the `image:` line on nextgen-dast:
#   image: dockerregistry.fairtprm.com/nextgen-dast:2.1.2

./pentest.sh pull
./pentest.sh up -d
```

The MariaDB volume is preserved across upgrades. If a release adds new
columns/tables, the application's `reset.py` script applies them
idempotently (it's run automatically on container start).

### Backups

Two things matter:

1. **`data/mariadb/`** — the entire database. Stop the stack
   (`./pentest.sh down`), tar it up, store it offsite. Don't try to
   back it up while running — InnoDB will be in inconsistent state.
2. **`data/scans/` and `data/reports/`** — scan artifacts and generated
   PDFs. Safe to back up live with `rsync`.

The `.env_<hex>` file and the secrets file under `data/` are also
critical — losing the env file means losing the database password.

---

## Files in the deploy directory

| Path | Purpose | Required? |
|---|---|---|
| `docker-compose.yml` | Defines the application + MariaDB stack | **yes** |
| `setup.sh` | First-time setup helper | yes (for first install) |
| `pentest.sh` | Day-2 wrapper around `docker compose` | recommended |
| `db/schema.sql` | Schema applied to MariaDB on first boot | **yes** |
| `.env.example` | Documented template for the env file | reference only |
| `.env_<hex>` | Generated by setup.sh, contains all secrets | **yes** (chmod 600) |
| `Dockerfile` | Used only when building locally (`--build`) | optional |
| `app/`, `scripts/`, `toolkit/` | Python source (used only when building) | optional |
| `data/` | Created at runtime; holds DB, scans, reports, secrets | created automatically |

---

## Troubleshooting

### `setup.sh` says "cannot pull image" / "Cannot reach the registry"
The image is public, so this is almost always a network problem rather
than an auth one. Walk down the list:

1. **DNS / outbound HTTPS to the registry:**
   `curl -sI https://dockerregistry.fairtprm.com/v2/` should print
   `HTTP/2 200`. If it fails, your firewall, corporate proxy, or DNS
   resolver is blocking outbound HTTPS to that host.
2. **Behind an HTTP proxy?** Add the proxy to Docker:
   `sudo systemctl edit docker.service` → in the override file:
   ```
   [Service]
   Environment="HTTP_PROXY=http://proxy.corp:3128"
   Environment="HTTPS_PROXY=http://proxy.corp:3128"
   ```
   Then `sudo systemctl daemon-reload && sudo systemctl restart docker`
   and re-run setup.
3. **Private mirror or registry policy changed:** if your administrator
   has switched the registry to require authentication, run
   `docker login dockerregistry.fairtprm.com` once with your credentials,
   then re-run setup.
4. **Air-gapped install:** skip the registry entirely with
   `sudo ./setup.sh --build` — the image is built from the local
   source tree.

### Login page redirects in a loop
Almost always a TLS issue. The session cookie is `Secure`-only — it won't
get set over plain HTTP. Confirm you're hitting the app over HTTPS via the
reverse proxy, not directly on port 8888.

### "MariaDB didn't become healthy in time"
The most common cause is a corrupted `data/mariadb/` directory from a
previous failed run. If this is a fresh setup with no important data:
`sudo rm -rf data/mariadb && sudo ./setup.sh` will start clean. If you
have data you want to keep, look at
`./pentest.sh logs mariadb` for the actual error.

### "permission denied" on `data/mariadb/`
On RHEL/Oracle Linux with SELinux enforcing, you may need to label the
directory:
```bash
sudo chcon -Rt container_file_t /data/pentest/data
```

### Docker pulls fine as your user but `setup.sh` fails to pull
This only matters if your registry has been switched to private mode and
you've run `docker login`. In that case the credentials live in
`~/.docker/config.json` of whichever user logged in. If you logged in as
your normal user but ran `setup.sh` with `sudo`, root doesn't see those
credentials. Either log in as root (`sudo docker login …`) or, after
Docker is installed and you've been added to the `docker` group, re-run
setup without sudo.

### Forgot the admin password
```bash
./pentest.sh reset
# Re-prints the new admin password and rewrites the secrets file.
# All assessments and findings are preserved — only the admin user is
# rotated.
```

### Need to start completely over
```bash
./pentest.sh down
sudo rm -rf data .env_*
sudo ./setup.sh
```

---

## Architecture, briefly

```
                                ┌──────────────────────────┐
   browser ── HTTPS ── nginx ──>│ nextgen-dast:8888 (app)  │── MariaDB:13306
                                │  fastapi + jinja2        │      │
                                │  spawns scanner subps    │      │
                                │  reads /data/* artifacts │      │
                                └──────────────────────────┘      │
                                            │                     │
                                            └─── /data/mariadb ───┘
```

Everything except TLS termination runs inside containers. The application
container itself spawns scanner subprocesses (wapiti, nuclei, etc.) — they
all live in the same image, so no extra installs on the host.
