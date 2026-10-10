# Xhip

Lightweight, secure CLI for shipping private project source code from a local machine to any VPS using Cloudflare R2 object storage and temporary presigned URLs.

The VPS never needs Cloudflare R2 credentials.

---

## Installation

### Debian / Ubuntu
```bash
sudo apt install ./xhip.deb
```

### From source
```bash
cargo install --path .
```

---

## Usage

### 1. Configure R2 credentials (local machine only)
```bash
xhip setup
```

Check configuration:
```bash
xhip status
```

### 2. Push project source
```bash
# In your project folder
xhip push

# Or preview packaging in a tree view first:
xhip push --dry-run
```
> [!NOTE]
> When run for the first time, Xhip automatically generates `.xhipignore` in your project with default exclusions (`.env`, `.git`, `node_modules`, build artifacts, keys). Edit `.xhipignore` to customize exclusions.

### 3. Generate a temporary download URL
```bash
xhip link <project-name>
```

Output:
```text
Project:  <project-name> (v20261010093011, 10m expiry)
URL:      https://<account-id>.r2.cloudflarestorage.com/...

Pull command for VPS:
  xhip pull --url "https://..."
```

### 4. Pull and deploy on VPS
```bash
# Using the generated command
xhip pull --url "<shipping-url>"

# Or specify destination directory:
xhip pull --url "<shipping-url>" --dir /opt/apps/my-app

# Or prompt interactively:
xhip pull
```

---

## Commands

- `xhip setup` — configure and validate Cloudflare R2 credentials
- `xhip push [PATH] [--name NAME] [--dry-run]` — package and upload project source
- `xhip link NAME [--version VER] [--expires MIN]` — generate temporary presigned download URL
- `xhip pull [--url URL] [--dir PATH]` — download and safely deploy archive
- `xhip list [NAME]` — list uploaded projects and versions
- `xhip status` — check configuration status
- `xhip --help` — show help

---

## Security

- R2 credentials exist only on the trusted local workstation (`0600` permissions).
- Presigned URLs are short-lived bearer credentials (default 10 minutes).
- Sensitive files (`.env`, private keys) and build caches are excluded by default via `.xhipignore`.
- Archives are checked for path traversal (`..` attacks) and verified via SHA-256 manifest.
- VPS deployments preserve existing runtime data (`.env`, SQLite databases, uploads).
