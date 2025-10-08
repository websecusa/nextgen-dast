#!/usr/bin/env bash
# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
#
# nextgen-dast — first-time setup helper.
#
# Designed to be safe to run multiple times: every step checks for the
# expected end state before doing anything. Run with sudo on a fresh
# Ubuntu / Debian / Kali / RHEL / Oracle Linux machine and it will:
#
#   1. Detect the OS and install Docker Engine + Compose plugin if missing.
#   2. Make sure the current invoking user is in the `docker` group (so they
#      don't need sudo for day-2 ops).
#   3. Verify you can pull the application image from the private registry.
#      If you're not logged in yet, it tells you how.
#   4. Generate a random .env_<suffix> file with strong secrets if one is
#      not already present in this directory.
#   5. Pull the image, start the stack, wait for MariaDB to be healthy,
#      run the schema migration / admin-user seeding step.
#   6. Print where to find the freshly generated admin password.
#
# Usage:
#   sudo ./setup.sh
#   sudo ./setup.sh --build       # build the image locally instead of pulling
#   sudo ./setup.sh --no-install  # skip Docker installation (assume present)
#
set -euo pipefail
cd "$(dirname "$0")"

REGISTRY_HOST="dockerregistry.fairtprm.com"
IMAGE="${REGISTRY_HOST}/nextgen-dast:2.1.1"
DEPLOY_DIR="$(pwd)"

# ---- Logging ---------------------------------------------------------------

log()  { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- Privilege check -------------------------------------------------------

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "Run me with sudo or as root: 'sudo ./setup.sh'"
    fi
}

# ---- OS detection ----------------------------------------------------------

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        die "Can't read /etc/os-release. Unsupported OS — install Docker manually, then re-run with --no-install."
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-}"
    OS_ID_LIKE="${ID_LIKE:-}"
    OS_VERSION_ID="${VERSION_ID:-}"
    OS_CODENAME="${VERSION_CODENAME:-}"
    log "Detected OS: ${PRETTY_NAME:-$OS_ID} (id=${OS_ID}, like=${OS_ID_LIKE})"
}

# Returns the family: 'debian' or 'rhel'. Anything else => unsupported.
os_family() {
    case "$OS_ID" in
        ubuntu|debian|kali) echo "debian"; return ;;
        rhel|centos|rocky|almalinux|ol|fedora|amzn) echo "rhel"; return ;;
    esac
    case "$OS_ID_LIKE" in
        *debian*) echo "debian"; return ;;
        *rhel*|*fedora*) echo "rhel"; return ;;
    esac
    echo "unsupported"
}

# ---- Docker install --------------------------------------------------------

docker_present() {
    command -v docker >/dev/null 2>&1 \
        && docker compose version >/dev/null 2>&1
}

install_docker_debian() {
    # Official Docker repo. The exact codename matters — Kali maps to
    # the matching Debian release; on unknown codenames we fall back to
    # 'bookworm' which the Docker repo carries.
    local codename="$OS_CODENAME"
    if [[ "$OS_ID" == "kali" ]]; then
        codename="bookworm"
    fi

    log "Installing Docker Engine (debian/ubuntu family)..."
    apt-get update -qq
    apt-get install -y -qq \
        ca-certificates curl gnupg lsb-release

    # Docker GPG key
    install -m 0755 -d /etc/apt/keyrings
    if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
        local repo_id="$OS_ID"
        # Kali piggy-backs on the debian repo
        [[ "$OS_ID" == "kali" ]] && repo_id="debian"
        curl -fsSL "https://download.docker.com/linux/${repo_id}/gpg" \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
    fi

    local repo_id="$OS_ID"
    [[ "$OS_ID" == "kali" ]] && repo_id="debian"
    cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${repo_id} ${codename} stable
EOF

    apt-get update -qq
    apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
}

install_docker_rhel() {
    log "Installing Docker Engine (rhel/oracle family)..."
    local repo_id="$OS_ID"
    # Oracle Linux uses the centos repo from Docker
    case "$OS_ID" in
        ol|oracle) repo_id="centos" ;;
        rocky|almalinux) repo_id="centos" ;;
        rhel) repo_id="rhel" ;;
        fedora) repo_id="fedora" ;;
    esac

    if command -v dnf >/dev/null 2>&1; then
        dnf -y install dnf-plugins-core
        dnf config-manager --add-repo \
            "https://download.docker.com/linux/${repo_id}/docker-ce.repo"
        dnf -y install docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
    elif command -v yum >/dev/null 2>&1; then
        yum install -y yum-utils
        yum-config-manager --add-repo \
            "https://download.docker.com/linux/${repo_id}/docker-ce.repo"
        yum install -y docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
    else
        die "Neither dnf nor yum is available. Install Docker manually."
    fi

    systemctl enable --now docker
}

ensure_docker() {
    if docker_present; then
        log "Docker + compose already installed: $(docker --version)"
        return
    fi
    case "$(os_family)" in
        debian) install_docker_debian ;;
        rhel)   install_docker_rhel ;;
        *)      die "Unsupported OS '${OS_ID}'. Install Docker manually then re-run with --no-install." ;;
    esac
    systemctl enable --now docker || true
    log "Docker installed: $(docker --version)"
}

ensure_user_in_docker_group() {
    # SUDO_USER is set when the script is invoked via sudo. If we're root
    # without a SUDO_USER (e.g. running as actual root on a fresh box),
    # there's no per-user account to add to the group.
    local target_user="${SUDO_USER:-}"
    if [[ -z "$target_user" || "$target_user" == "root" ]]; then
        return
    fi
    if id -nG "$target_user" | grep -qw docker; then
        return
    fi
    log "Adding '${target_user}' to the docker group (log out/in to take effect)"
    usermod -aG docker "$target_user"
}

# ---- Registry login --------------------------------------------------------

ensure_registry_login() {
    # In --build mode we'll build from the local source, so we don't need
    # to reach the registry at all.
    if [[ "${BUILD_MODE:-0}" == "1" ]]; then
        return
    fi
    # The registry is public — pull is anonymous. If this fails, it's
    # almost always a network / DNS / corporate-proxy issue, not auth.
    if docker pull --quiet "$IMAGE" >/dev/null 2>&1; then
        log "Registry image is accessible: $IMAGE"
        return
    fi
    cat <<EOF >&2

==============================================================================
  Cannot pull $IMAGE

  The application image is published as PUBLIC — no docker login is
  required to pull it. This failure is almost always a network problem.
  Check, in order:

    1. DNS + outbound HTTPS to the registry:
         curl -sI https://${REGISTRY_HOST}/v2/
       (should print HTTP/2 200)

    2. Corporate HTTP proxy: configure docker via
         sudo systemctl edit docker.service
       and set HTTP_PROXY / HTTPS_PROXY in the override.

    3. Registry policy change: if your administrator has switched the
       registry to require authentication, run
         docker login ${REGISTRY_HOST}
       once and re-run setup.

    4. Air-gapped / no network at all: skip the registry and build the
       image from the local source tree:
         sudo ./setup.sh --build
==============================================================================
EOF
    exit 2
}

# ---- Env file --------------------------------------------------------------

generate_env_file() {
    # 1. Reuse an existing env file IFF it's the random-suffixed kind we
    #    generate. We deliberately ignore plain `.env` here — that filename
    #    is the first thing automated scrapers grep for, so we don't want to
    #    encourage its use, and we refuse to run with one (see below).
    local existing
    existing=$(ls -1 .env_[0-9a-f]* 2>/dev/null | head -1 || true)
    if [[ -n "$existing" ]]; then
        log "Reusing existing env file: $existing"
        validate_env_file "$existing"
        ENV_FILE="$existing"
        return
    fi
    # 2. Refuse to silently use a hand-authored `.env` — if someone copied
    #    .env.example and forgot to fill it in, the placeholder secrets would
    #    silently become production secrets. Hard fail with instructions.
    if [[ -f .env ]]; then
        die "Found a plain '.env' file. Rename it to '.env_$(openssl rand -hex 8)' so it doesn't match common secret-file scrapers, then re-run setup.sh. Or delete it to have setup.sh generate a fresh one."
    fi

    # 3. Fresh install. Every secret below is generated locally — there is
    #    no shared default password. The env-file suffix is itself random
    #    so two installs on the same host don't collide and so attackers
    #    looking for `.env` (the conventional name) miss this one.
    local suffix root_pw app_pw app_secret
    suffix=$(openssl rand -hex 8)            # 64 bits — same scheme as pentest.sh
    root_pw=$(openssl rand -hex 24)          # MariaDB root, 192 bits
    app_pw=$(openssl rand -hex 24)           # MariaDB app user, 192 bits
    app_secret=$(openssl rand -hex 32)       # session cookie key, 256 bits

    ENV_FILE=".env_${suffix}"
    umask 077
    cat > "$ENV_FILE" <<EOF
# Generated by setup.sh on $(date -u +%FT%TZ). Every value below is random
# per-install. Never commit this file. Never share it. chmod 600.
ENV_SUFFIX=${suffix}
MARIADB_ROOT_PASSWORD=${root_pw}
MARIADB_DATABASE=pentest
MARIADB_USER=pentest
MARIADB_PASSWORD=${app_pw}
SECRETS_FILE=/data/.sensitive_secrets_info_${suffix}
APP_URL=${APP_URL:-https://localhost/}
APP_SECRET=${app_secret}
EOF
    chmod 600 "$ENV_FILE"

    log "Generated env file: ${ENV_FILE} (chmod 600)"
    log "  • Suffix: random 8-byte hex (this filename won't be discovered by '.env'-scrapers)"
    log "  • MariaDB root password: 24-byte random hex (independent of every other install)"
    log "  • MariaDB app password:  24-byte random hex (independent of every other install)"
    log "  • Application secret:    32-byte random hex (signs every session cookie)"
    log "  • Admin password:        will be generated by reset.py in step 6 and saved to ${SECRETS_FILE_HOST_HINT:-data/.sensitive_secrets_info_${suffix}}"
    log "  • APP_URL: ${APP_URL:-https://localhost/}  (edit ${ENV_FILE} to change)"
}

# Sanity-check an env file before we actually use it. Catches the case
# where a user copied .env.example to .env_<suffix> by hand and forgot to
# replace the 'changeme' placeholders — running with those would mean a
# shared, published, well-known root password in production.
validate_env_file() {
    local file=$1 bad=()
    if grep -qE '^(MARIADB_ROOT_PASSWORD|MARIADB_PASSWORD|APP_SECRET)=changeme' "$file"; then
        bad+=("contains 'changeme-*' placeholder values from .env.example")
    fi
    if grep -qE '^(MARIADB_ROOT_PASSWORD|MARIADB_PASSWORD|APP_SECRET)=$' "$file"; then
        bad+=("contains an empty secret value")
    fi
    # Length floor: anything under 16 chars on these fields means someone
    # set a weak value by hand. Real generated values are 48+ chars.
    while IFS='=' read -r key val; do
        case "$key" in
            MARIADB_ROOT_PASSWORD|MARIADB_PASSWORD|APP_SECRET)
                if (( ${#val} < 16 )); then
                    bad+=("$key is shorter than 16 chars (got ${#val})")
                fi ;;
        esac
    done < "$file"
    if ((${#bad[@]})); then
        printf '\033[1;31m[error]\033[0m env file %s has problems:\n' "$file" >&2
        printf '  - %s\n' "${bad[@]}" >&2
        die "Fix or delete the env file and re-run setup.sh — refusing to run with weak/default secrets."
    fi
}

# ---- Compose orchestration -------------------------------------------------

compose_file() {
    if [[ "${BUILD_MODE:-0}" == "1" ]]; then
        echo "docker-compose.yml"
    else
        echo "docker-compose.yml"
    fi
}

start_stack() {
    log "Starting the stack..."
    if [[ "${BUILD_MODE:-0}" == "1" ]]; then
        docker compose --env-file "$ENV_FILE" up -d --build
    else
        docker compose --env-file "$ENV_FILE" pull
        docker compose --env-file "$ENV_FILE" up -d
    fi
}

wait_for_db() {
    log "Waiting for MariaDB to become healthy (up to 2 minutes)..."
    local i=0
    until docker compose --env-file "$ENV_FILE" ps --format '{{.Service}} {{.Health}}' \
            | grep -q '^mariadb healthy$'; do
        i=$((i + 1))
        if [[ $i -gt 60 ]]; then
            docker compose --env-file "$ENV_FILE" logs --tail 50 mariadb >&2
            die "MariaDB didn't become healthy in time. See logs above."
        fi
        sleep 2
    done
    log "MariaDB is healthy."
}

run_reset() {
    log "Applying schema and seeding admin user..."
    docker compose --env-file "$ENV_FILE" exec -T nextgen-dast \
        python /app/scripts/reset.py
}

# ---- Main ------------------------------------------------------------------

main() {
    BUILD_MODE=0
    NO_INSTALL=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --build)      BUILD_MODE=1; shift ;;
            --no-install) NO_INSTALL=1; shift ;;
            -h|--help)
                grep -E '^#( |$)' "$0" | sed 's/^# \?//'
                exit 0 ;;
            *) die "Unknown flag: $1" ;;
        esac
    done

    require_root
    detect_os
    if [[ "$NO_INSTALL" == "0" ]]; then
        ensure_docker
        ensure_user_in_docker_group
    elif ! docker_present; then
        die "--no-install set but Docker isn't installed."
    fi

    if [[ ! -f docker-compose.yml ]]; then
        die "No docker-compose.yml in $(pwd). Run setup.sh from the deploy directory."
    fi
    if [[ "$BUILD_MODE" == "1" && ! -f Dockerfile ]]; then
        die "--build given but no Dockerfile in $(pwd)."
    fi

    ensure_registry_login
    generate_env_file
    start_stack
    wait_for_db
    run_reset

    local suffix
    suffix=$(grep -E '^ENV_SUFFIX=' "$ENV_FILE" | cut -d= -f2)
    local secrets_path="${DEPLOY_DIR}/data/.sensitive_secrets_info_${suffix}"

    cat <<EOF

==============================================================================
  Setup complete.

  Stack status:        docker compose --env-file ${ENV_FILE} ps
  Application logs:    docker compose --env-file ${ENV_FILE} logs -f nextgen-dast
  Stop the stack:      docker compose --env-file ${ENV_FILE} down

  Admin credentials are in:
      ${secrets_path}

  The application is listening on 127.0.0.1:8888 at the root path (/).
  Put a TLS-terminating reverse proxy (nginx, Caddy, etc.) in front of it
  to expose it on the public URL configured in ${ENV_FILE} (APP_URL).

  See README.md for nginx config examples and day-2 operations.
==============================================================================
EOF
}

main "$@"
