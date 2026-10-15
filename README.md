# Xhip

Lightweight, secure CLI for shipping private project source code from a local machine to any VPS using Cloudflare R2 object storage and temporary presigned URLs.

The VPS never needs Cloudflare R2 credentials.

---

## Installation

### One-Command Installer (Debian / Ubuntu amd64)
```bash
curl -fsSL https://onisa-jr.github.io/xhip/install.sh -o install.sh
sudo bash install.sh
```

### From Local Package / Source
```bash
# From .deb package
sudo apt install ./xhip.deb

# From source
cargo install --path .
```

---

## Usage

### 1. Configure R2 credentials (local machine only)
```bash
xhip setup
```

Check configuration and limits:
```bash
xhip status
```

### 2. Push project source
```bash
# In your project folder (auto-detects project name without prompting!)
xhip push

# Or push and immediately generate a shipping link in one command:
xhip push --link

# Or preview packaging in a clean tree view first:
xhip push --dry-run
```
> [!NOTE]
> **Smart `.xhipignore`**:
> When run for the first time, Xhip automatically copies your existing `.gitignore` into `.xhipignore`. If no `.gitignore` is present, it creates an empty `.xhipignore`. You can force re-sync at any time with `xhip push --sync-ignore`.
>
> Git metadata (`.git/`) and secrets (`.env`) are excluded by default.

### 3. Generate a temporary download link
```bash
# Inside your project folder (project name is auto-detected!)
xhip link

# Or explicitly for any project:
xhip link <project-name>
```

Clean, formatted output with automatic link shortening:
```text
╭────────────────────────────────────────────────────────────────────╮
│  🚀 XHIP SHIPPING LINK                                             │
╰────────────────────────────────────────────────────────────────────╯
  Project:        my-app
  Version:        v20261015054800
  Expires:        10 minutes

  🔗 Short Shipping Link:
     https://da.gd/MBHbr

  📋 VPS Pull Command (run on remote server):
     xhip pull --url "https://da.gd/MBHbr"

  🔒 Direct Storage URL:
     https://<account-id>.r2.cloudflarestorage.com/...
```

### 4. Pull and deploy on VPS
```bash
# Using the shortened shipping link
xhip pull --url "https://da.gd/MBHbr"

# Or specify destination directory:
xhip pull --url "https://da.gd/MBHbr" --dir /opt/apps/my-app

# Or prompt interactively:
xhip pull
```

---

## Commands

- `xhip setup` — configure and validate Cloudflare R2 credentials
- `xhip push [PATH] [--name NAME] [--link] [--sync-ignore] [--dry-run]` — package and upload project source (auto-detects project name)
- `xhip link [NAME] [--version VER] [--expires MIN] [--no-short]` — generate temporary shortened download link and VPS pull command
- `xhip pull [--url URL] [--dir PATH]` — download and safely deploy archive
- `xhip list [NAME]` — list uploaded projects and versions
- `xhip status` — check configuration status and upload limits
- `xhip --help` — show help and guidelines

---

## Storage Limits & Large Files

| Parameter | Limit / Recommendation | Details |
|---|---|---|
| **Max Archive Size** | **5 GB** | Hard single PUT object upload limit imposed by Cloudflare R2 / S3. |
| **Recommended Size** | **< 500 MB** | For fast packaging, uploads, and remote VPS deployments. |
| **Large File Warning** | **50 MB** | Xhip warns during scanning if files $\ge$ 50 MB are packaged so you can add them to `.xhipignore` if unnecessary. |
| **Streaming Memory** | **64 KB Buffer** | Files are hashed via streaming chunks, preventing RAM exhaustion on large files. |

---

## Security

- R2 credentials exist only on the trusted local workstation (`0600` permissions).
- Presigned URLs are short-lived bearer credentials (default 10 minutes).
- Sensitive files (`.env`, private keys) and `.git` are excluded by default.
- Archives are checked for path traversal (`..` attacks) and verified via SHA-256 manifest.
- VPS deployments preserve existing live runtime data (`.env`, SQLite databases, uploads).
