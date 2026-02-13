# Unraid Service Lens

Tired of not remembering the hostnames, IPs, and ports of all your self-hosted services? Find the Unraid GUI too cramped to use as a daily launcher? Service Lens is a lightweight dashboard that auto-discovers every Docker container and VM on your Unraid server and puts them all in one clean, clickable page — no manual configuration, no fluff.

## Key Benefits

1. **One page for all your services** — Auto-discovers every Docker container and VM on your Unraid server. Click any service to open its admin page. View console logs. Start, stop, or restart containers. No bookmarks to maintain, no YAML to write.

2. **Built with authentication** — Session-based login with bcrypt password hashing and configurable session duration (1 hour to 1 year). Rate-limited login attempts. Your dashboard, your credentials.

3. **Just needs an Unraid API key** — Create a key in your [Unraid API settings](https://docs.unraid.net/unraid-os/manual/users/api-keys/) and paste it into the setup wizard. That's it.

## Features

- **Auto-discovery** — Detects all Docker containers and VMs via the Unraid GraphQL API. Resolves web UI URLs automatically from Docker labels, handling bridge, macvlan, and container-mode networking.
- **Container logs** — View live container logs directly in the dashboard via the Docker socket. No SSH needed.
- **Real-time system metrics** — CPU, memory, temperature, and uptime at a glance. Auto-refreshes every 30 seconds.
- **Card and compact views** — Switch between visual cards with icons or a dense table view. Customize visible columns with drag-and-drop reordering.
- **Collapsible sections and filters** — Collapse Containers or VMs independently. Filter to show only running services. All state persists across sessions.
- **First-run setup wizard** — Guided 2-step onboarding: create your account, then connect to Unraid. No config files to edit.
- **Dark theme** — Ships dark by default. Light and system themes also available.

## Screenshots

> _Screenshots coming soon._

## Quick Start

### Docker Compose (recommended)

```yaml
services:
  service-lens:
    image: ghcr.io/fernandoslee/service-lens:latest
    container_name: service-lens
    ports:
      - "8080:8080"
    volumes:
      - service-lens-data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped

volumes:
  service-lens-data:
```

```bash
docker compose up -d
```

Then open `http://<your-server-ip>:8080` and follow the setup wizard.

### Docker Run

```bash
docker run -d \
  --name service-lens \
  -p 8080:8080 \
  -v service-lens-data:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --restart unless-stopped \
  ghcr.io/fernandoslee/service-lens:latest
```

## Setup

On first launch, the setup wizard guides you through two steps:

1. **Create account** — Choose a username and password (minimum 8 characters).
2. **Connect to Unraid** — Enter your server's IP address and an [API key](https://docs.unraid.net/unraid-os/manual/users/api-keys/).

> **Note:** Use the server's IP address (e.g., `192.168.1.100`), not a `.local` hostname. mDNS/Bonjour names like `tower.local` do not resolve inside Docker containers.

### API Key Permissions

Create an API key in your Unraid settings with the following permissions:

| Permission | Required | Used for |
|---|---|---|
| `DOCKER:READ_ANY` | Yes | List containers, status, labels, ports |
| `VMS:READ_ANY` | Yes | List VMs and state |
| `INFO:READ_ANY` | Yes | System info and metrics |
| `DOCKER:UPDATE_ANY` | Optional | Start, stop, restart containers |

An **Admin** role key works out of the box. If you create a custom key, the setup wizard will verify which permissions are available and warn you about any missing ones. Without `DOCKER:UPDATE_ANY`, the start/stop/restart buttons will be greyed out.

You can create a pre-configured API key by navigating to:

```
http://<your-server-ip>/Settings/ManagementAccess/ApiKeys/New?name=servicelens+api+key&scopes=info%2Bvms%3Aread_any%2Cdocker%3Aread_any%2Bupdate_any
```

This template includes all required permissions plus `DOCKER:UPDATE_ANY` for container control. You can also create the key manually in **Settings > Management Access > API Keys**.

### Docker Socket (for container logs)

Mount the Docker socket as a read-only volume to enable container log viewing:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

Permissions are configured automatically at runtime — no manual GID setup needed.

## Configuration

All configuration is managed through the Settings page in the web UI. Settings persist in a Docker volume.

| Setting | Description | Default |
|---------|-------------|---------|
| Unraid Host | Server hostname or IP | _(set during setup)_ |
| API Key | Unraid GraphQL API key | _(set during setup)_ |
| Verify SSL | Validate Unraid's SSL certificate | `false` |
| Session Duration | How long login sessions last | 1 day |
| Default View | Card or compact table | Cards |
| Show Containers | Display containers section | `true` |
| Show VMs | Display VMs section | `true` |

## Requirements

- **Unraid 7.x** (GraphQL API is built-in since 7.0)
- **Docker** on the host
- An **API key** — Admin role or custom key with permissions listed above ([how to create one](https://docs.unraid.net/unraid-os/manual/users/api-keys/))

## Tech Stack

- **Backend**: Python 3.11 / FastAPI / Uvicorn
- **Frontend**: Jinja2 + HTMX + Pico CSS (no JavaScript build step)
- **Data**: Unraid GraphQL API via [`unraid-api`](https://pypi.org/project/unraid-api/)
- **Logs**: Docker socket via [`docker-py`](https://pypi.org/project/docker/)

## Development

```bash
git clone https://github.com/fernandoslee/unraid-service-lens-dashboard.git
cd unraid-service-lens-dashboard
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run locally
UNRAID_HOST=tower.local UNRAID_API_KEY=<key> uvicorn app.main:app --port 8080

# Run tests (191 tests)
python -m pytest tests/ -q
```

## Security

- Passwords hashed with **bcrypt**
- Login **rate-limited** (10 attempts per 5-minute window)
- Signed session cookies with **SameSite=Lax**
- Docker socket mounted **read-only**
- Runs as **non-root user**
- Host input validated against injection patterns
- Atomic `.env` writes (crash-safe)

## License

MIT
