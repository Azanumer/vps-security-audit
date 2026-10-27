# vps-security-audit

A one-shot VPS security posture check: SSH hardening, firewall state, unattended upgrades, pending security updates, unexpected listening ports, SSH brute-force volume, and world-writable web files.

## Usage

```bash
bash audit.sh                 # human-readable report
bash audit.sh --json          # machine-readable report (cron / monitoring)
bash audit.sh --webroot /var/www/mysite
```

## Exit codes

- `0` — all checks pass
- `1` — warnings only (e.g. pending updates, unusual ports)
- `2` — at least one FAIL (root SSH login, firewall off, world-writable web files)
- `3` — usage error

## Notes

- SSH checks use `sshd -T` (effective config), so commented-out lines in sshd_config can't fool it.
- Read-only: it never changes a setting, only reports.

## License

MIT
