# Host-side deployment hardening (nextgen-dast 2.1.1)

These configs live in the source tree but are NOT applied automatically
by the Docker image — they belong on the **host running nginx and
fail2ban** in front of `nextgen-dast`. They are drafts; review the
placeholders before installing.

## Why these exist

The application's auth surface is now CSRF-protected and audit-logged
inside the container (see `app/audit.py`, `app/server.py`). What it
still lacks — by design, because it has to be solved at the perimeter
— is a brute-force throttle and a way to ban repeat offenders without
also banning the load balancer.

## Files

| Path | Goes on host at |
|---|---|
| `nginx/login-rate-limit.conf` | `/etc/nginx/conf.d/nextgen-dast-login.conf` |
| `fail2ban/filter.d/nextgen-dast-login.conf` | `/etc/fail2ban/filter.d/nextgen-dast-login.conf` |
| `fail2ban/jail.d/nextgen-dast-login.conf` | `/etc/fail2ban/jail.d/nextgen-dast-login.conf` |

## Install order

1. **Edit `set_real_ip_from`** in the nginx snippet to match your
   load-balancer egress CIDR. Without this, nginx will attribute every
   request to the LB's own IP — and fail2ban will ban the LB on the
   first burst, which takes the whole site offline.
2. `nginx -t && systemctl reload nginx`.
3. **Edit `ignoreip`** in the fail2ban jail to include the LB and any
   trusted office / monitoring networks.
4. `fail2ban-client reload`.
5. Tail `/var/log/fail2ban.log` and `/data/pentest/data/logs/auth_events.jsonl`
   to verify hits flow through both layers.
