# Practice targets (lab)

WebVAST is for testing applications **you own or are authorized to test**. For
development and your project demo, use a deliberately-vulnerable practice app.

## Option A — bundled demo target (no Docker needed)

The project ships a tiny intentionally-vulnerable Flask app that exercises all
four scanner modules:

```bash
cd backend
. .venv/bin/activate
python demo_target/app.py        # http://localhost:5001
```

Scan `http://localhost:5001` from the dashboard. Expected findings: SQL
injection (`/search`), reflected + stored XSS (`/greet`, `/guestbook`),
misconfiguration (missing headers, insecure cookie, exposed `/.env`), and
outdated jQuery / Bootstrap.

## Option B — industry-standard vulnerable apps (Docker)

If you have Docker, the `docker-compose.yml` here starts OWASP **Juice Shop**
and **DVWA**, both bound to `127.0.0.1` only:

```bash
docker compose -f lab/docker-compose.yml up -d
# Juice Shop -> http://localhost:3000
# DVWA       -> http://localhost:8081  (login admin / password, then "Create / Reset Database")
docker compose -f lab/docker-compose.yml down   # when finished
```

> ⚠️ These apps are intentionally insecure. Never expose them to the internet
> or a shared network. Keep them bound to localhost and shut them down when done.
