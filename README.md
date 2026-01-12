# spritesync

> [!WARNING]
> This is experimental software. Use at your own risk.
> - May corrupt files or directories if sync conflicts occur
> - May prevent Sprites from hibernating (services keep running)
> - Not recommended for critical data without backups

Sync directories between [Sprites](https://sprites.dev) using [Syncthing](https://syncthing.net) over [Tailscale](https://tailscale.com).

## Features

- **Mesh sync** - All devices sync with each other, no single point of failure
- **Zero-config** - `create` once, `join` from anywhere on your tailnet
- **Auto-discovery** - Devices find each other automatically
- Secure peer-to-peer sync over Tailscale (no public relays)
- Works with systemd or Sprite service managers

## Quick Start

### Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kylemclaren/spritesync/main/install.sh)
```

### Create a Sync Group (first Sprite)

```bash
spritesync create skills ~/.claude/skills
```

### Join from Other Sprites

```bash
spritesync join skills
```

That's it. All devices with the same group sync in a mesh.

## Usage

### Mesh Sync (Recommended)

Create a named sync group that any device can join:

```bash
# On first Sprite - create the group
spritesync create myproject ~/code/myproject

# On every other Sprite - just join
spritesync join myproject
```

The `join` command:
1. Discovers the group on the tailnet
2. Connects to ALL existing members
3. Starts syncing immediately

### Direct Sync

For one-off syncs between two specific devices:

```bash
spritesync sync ~/projects sprite-b
```

### Other Commands

```bash
spritesync groups              # List sync groups on this device
spritesync status              # Show folder sync status
spritesync devices             # Discover devices on tailnet
spritesync unsync ~/projects   # Stop syncing a directory
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `spritesync create <name> <dir>` | Create a named sync group |
| `spritesync join <name>` | Join an existing sync group |
| `spritesync groups` | List sync groups on this device |
| `spritesync sync <dir> <device>` | Direct sync with a specific device |
| `spritesync unsync <dir>` | Stop syncing a directory |
| `spritesync status [--json]` | Show folder sync status |
| `spritesync devices [--json]` | Discover spritesync devices on tailnet |
| `spritesync info` | Show this device's ID and hostname |
| `spritesync serve` | Run discovery service (managed by installer) |

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

1. **Discovery service** (port 8385) - Devices advertise sync groups and find each other
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
| spritesync | 8385 | Device/group discovery (Tailscale IP only) |

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

## License

MIT
