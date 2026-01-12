# spritesync

Sync directories between [Sprites](https://sprites.dev) using [Syncthing](https://syncthing.net) over [Tailscale](https://tailscale.com).

## Features

- **Zero-config pairing** - Devices auto-discover each other on the tailnet
- Secure peer-to-peer directory sync over Tailscale
- Tailnet membership = trust (no manual device ID exchange)
- Deterministic folder IDs for reliable reconnection
- Works with systemd or Sprite service managers

## Quick Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kylemclaren/spritesync/main/install.sh)
```

The installer will:
1. Install Syncthing and Tailscale
2. Configure Syncthing to listen only on your Tailscale IP
3. Disable global/local discovery and relays for privacy
4. Set up Syncthing and spritesync as persistent services
5. Install the Claude Code skill (on Sprite environments)

## Usage

### Sync a Directory

```bash
# On Sprite A
spritesync sync ~/projects sprite-b
```

That's it. spritesync automatically:
1. Discovers sprite-b on the tailnet
2. Exchanges Syncthing device IDs
3. Creates the shared folder
4. sprite-b auto-accepts the folder

### Discover Devices

```bash
spritesync devices
```

Scans the tailnet for other devices running spritesync.

### Check Status

```bash
spritesync status
spritesync status --json
```

### Stop Syncing

```bash
spritesync unsync ~/projects
```

Files are not deleted, only removed from sync.

## CLI Reference

| Command | Description |
|---------|-------------|
| `spritesync serve` | Run discovery service (managed by installer) |
| `spritesync sync <dir> <device>` | Sync a directory with another device |
| `spritesync unsync <dir>` | Stop syncing a directory |
| `spritesync status [--json]` | Show folder sync status |
| `spritesync devices [--json]` | Discover spritesync devices on tailnet |
| `spritesync info` | Show this device's ID and hostname |
| `spritesync version` | Print version |

## How It Works

```
┌─────────────┐      ┌─────────────────┐
│ spritesync  │─────▶│ Syncthing REST  │
│ (Go CLI)    │      │ 127.0.0.1:8384  │
└─────────────┘      └─────────────────┘
       │                      │
       ▼                      ▼
┌─────────────┐      ┌─────────────────┐
│ Discovery   │      │ Syncthing P2P   │
│ :8385       │      │ :22000          │
└─────────────┘      └─────────────────┘
       │                      │
       └──────────────────────┘
                  │
                  ▼
           ┌─────────────┐
           │ Tailscale   │
           │ 100.x.x.x   │
           └─────────────┘
```

1. **Discovery service** (port 8385) - Allows devices to find each other
2. **Syncthing** handles actual file synchronization
3. **Tailscale** provides the secure network layer

All traffic stays within your Tailscale network. No discovery servers, relays, or external connections.

## Recommended Setup

For multiple Sprites, create a dedicated tailnet using a new GitHub organization:

1. Create a new GitHub org (e.g., `myproject-sprites`)
2. Sign up for [Tailscale](https://tailscale.com) using that org
3. Install spritesync on each Sprite - they'll automatically join the same tailnet

## Services

The installer sets up two services:

| Service | Port | Purpose |
|---------|------|---------|
| syncthing | 22000 | File synchronization (Tailscale IP only) |
| spritesync | 8385 | Device discovery (Tailscale IP only) |

### Sprite Environment

```bash
sprite-env services get syncthing
sprite-env services get spritesync
```

### systemd

```bash
systemctl status syncthing@$USER
systemctl status spritesync@$USER
```

## Building from Source

```bash
git clone https://github.com/kylemclaren/spritesync.git
cd spritesync
go build -o spritesync .
```

## Manual Installation

Download the binary for your platform from [Releases](https://github.com/kylemclaren/spritesync/releases):

```bash
# Linux amd64
curl -fsSL https://github.com/kylemclaren/spritesync/releases/latest/download/spritesync-linux-amd64 -o spritesync
chmod +x spritesync
sudo mv spritesync /usr/local/bin/
```

Then run the discovery service:

```bash
spritesync serve
```

## License

MIT
