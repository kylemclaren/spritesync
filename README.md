# spritesync

Sync directories between [Sprites](https://sprites.dev) using [Syncthing](https://syncthing.net) over [Tailscale](https://tailscale.com).

## Features

- Secure peer-to-peer directory sync over your Tailscale network
- Device pairing via Taildrop - no manual device ID exchange
- Automatic folder sharing with autoAcceptFolders
- Deterministic folder IDs for reliable reconnection
- Works with systemd or Sprite service managers

## Recommended Setup

For multiple Sprites, create a dedicated tailnet using a new GitHub organization:

1. Create a new GitHub org (e.g., `myproject-sprites`)
2. Sign up for [Tailscale](https://tailscale.com) using that org
3. Install spritesync on each Sprite - they'll automatically join the same tailnet

## Quick Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kylemclaren/spritesync/main/install.sh)
```

The installer will:
1. Install Syncthing (via apt repo)
2. Install Tailscale (if not present)
3. Configure Syncthing to listen only on your Tailscale IP
4. Disable global/local discovery and relays for privacy
5. Set up Syncthing as a persistent service
6. Install the Claude Code skill (on Sprite environments)

## Usage

### Complete Workflow Example

**On Sprite A:**
```bash
# Pair with another Sprite
spritesync pair sprite-b

# Sync a directory
spritesync sync ~/projects sprite-b
```

**On Sprite B (simultaneously):**
```bash
# Pair with Sprite A
spritesync pair sprite-a

# The ~/projects folder will auto-accept from Sprite A
```

Both Sprites now sync the `~/projects` directory bidirectionally.

### CLI Commands

#### `spritesync init`

Initialize configuration and generate API key.

```bash
spritesync init
```

Creates `~/.config/spritesync/apikey`.

#### `spritesync info`

Show this device's Syncthing device ID and Tailscale hostname.

```bash
spritesync info
```

Output:
```
Syncthing Device ID: XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX
Tailscale Hostname:  my-sprite
```

#### `spritesync status`

Show folder sync status.

```bash
spritesync status
spritesync status --json
```

#### `spritesync pair <device>`

Pair with another device by exchanging Syncthing device IDs via Taildrop.

```bash
spritesync pair my-other-sprite
```

Both devices must run the pair command simultaneously. Paired devices will automatically accept shared folders from each other.

Options:
- `--timeout` - Timeout waiting for response (default: 5m)

#### `spritesync devices`

List all paired devices.

```bash
spritesync devices
spritesync devices --json
```

#### `spritesync sync <directory> <device>`

Sync a directory with another device.

```bash
spritesync sync ~/projects my-other-sprite
spritesync sync /data/shared backup-sprite
```

The folder ID is deterministic - the same directory synced to the same device will always use the same ID, allowing reconnection after restarts.

#### `spritesync unsync <directory>`

Remove a directory from sync.

```bash
spritesync unsync ~/projects
```

Files are not deleted, only removed from sync.

#### `spritesync version`

Print the version.

```bash
spritesync version
spritesync --version
```

### Claude Code Skill

On Sprite environments with Claude Code, the installer adds a `/spritesync` skill:

```
/spritesync              # Check sync status
/spritesync pair <dev>   # Pair with a device
/spritesync sync <dir> <dev>  # Sync a directory
```

## Building from Source

```bash
git clone https://github.com/kylemclaren/spritesync.git
cd spritesync
go build -o spritesync .
```

### Cross-compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o spritesync-linux-amd64 .

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o spritesync-linux-arm64 .

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -o spritesync-darwin-amd64 .

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o spritesync-darwin-arm64 .
```

## Manual Installation

Download the binary for your platform from [Releases](https://github.com/kylemclaren/spritesync/releases):

```bash
# Linux amd64
curl -fsSL https://github.com/kylemclaren/spritesync/releases/latest/download/spritesync-linux-amd64 -o spritesync
chmod +x spritesync
sudo mv spritesync /usr/local/bin/
```

## How It Works

1. **Syncthing** handles the actual file synchronization using its battle-tested sync protocol
2. **Tailscale** provides the secure network layer - Syncthing only listens on your Tailscale IP
3. **spritesync** simplifies device pairing and folder management through the CLI

All traffic stays within your Tailscale network. No discovery servers, relays, or external connections.

## License

MIT
