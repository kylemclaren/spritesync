#!/bin/bash
set -e

# spritesync installer
# Installs Syncthing, configures it for Tailscale-only access, and sets up services

REPO="kylemclaren/spritesync"
INSTALL_DIR="/usr/local/bin"
SYNCTHING_CONFIG_DIR="$HOME/.config/syncthing"
TS_HOSTNAME="${SPRITESYNC_HOSTNAME:-}"

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Status indicators
CHECK="${GREEN}+${NC}"
CROSS="${RED}x${NC}"
ARROW="${BLUE}->${NC}"

info()    { echo -e "  ${CHECK} $1"; }
warn()    { echo -e "  ${YELLOW}!${NC} $1"; }
error()   { echo -e "  ${CROSS} $1"; exit 1; }
step()    { echo -e "\n${BOLD}$1${NC}"; }
substep() { echo -e "  ${ARROW} $1"; }

# Generate random hostname
generate_hostname() {
    echo "sprite-$(tr -dc 'a-z0-9' < /dev/urandom | head -c 6)"
}

# Prompt for hostname or generate one
prompt_hostname() {
    # Skip if already set via env var
    [ -n "$TS_HOSTNAME" ] && return 0

    # Skip if already authenticated with a unique hostname
    if tailscale status > /dev/null 2>&1; then
        local current_name=$(tailscale status --json 2>/dev/null | jq -r '.Self.HostName // empty' 2>/dev/null)
        # If current hostname looks unique (contains random suffix), keep it
        if [[ "$current_name" =~ ^sprite-[a-z0-9]{6}$ ]]; then
            return 0
        fi
    fi

    # Prompt if running interactively
    if [ -t 0 ]; then
        echo ""
        echo -e "  ${DIM}Enter a unique hostname for this device in your tailnet${NC}"
        echo -e "  ${DIM}(e.g., sprite-api, sprite-dev, sprite-prod)${NC}"
        echo ""
        read -p "  Hostname [Enter to auto-generate]: " input_hostname

        if [ -n "$input_hostname" ]; then
            TS_HOSTNAME="$input_hostname"
        else
            TS_HOSTNAME=$(generate_hostname)
        fi
    else
        # Non-interactive: generate random hostname
        TS_HOSTNAME=$(generate_hostname)
    fi

    info "Device will be named: ${BOLD}${TS_HOSTNAME}${NC}"
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac

    case "$OS" in
        linux|darwin) ;;
        *) error "Unsupported OS: $OS" ;;
    esac

    PLATFORM="${OS}-${ARCH}"
}

# Check if running in Sprite environment
is_sprite() {
    [ -S "/.sprite/api.sock" ]
}

# Install dependencies
install_deps() {
    if ! command -v jq &> /dev/null; then
        substep "Installing jq..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update -qq > /dev/null 2>&1
            sudo apt-get install -y -qq jq > /dev/null 2>&1
        elif command -v yum &> /dev/null; then
            sudo yum install -y -q jq > /dev/null 2>&1
        elif command -v brew &> /dev/null; then
            brew install jq > /dev/null 2>&1
        fi
    fi

    if ! command -v curl &> /dev/null; then
        substep "Installing curl..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y -qq curl > /dev/null 2>&1
        fi
    fi

    if ! command -v xmllint &> /dev/null; then
        substep "Installing xmllint..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y -qq libxml2-utils > /dev/null 2>&1
        fi
    fi
}

# Install Tailscale if not present
install_tailscale() {
    if command -v tailscale &> /dev/null; then
        info "Tailscale $(tailscale version | head -1) installed"
        return 0
    fi

    substep "Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh 2>/dev/null | sh > /dev/null 2>&1
    info "Tailscale installed"
}

# Start tailscaled daemon
start_tailscaled() {
    if pgrep -x tailscaled > /dev/null; then
        info "tailscaled running"
        return 0
    fi

    if is_sprite; then
        substep "Creating tailscaled service..."
        sprite-env services delete tailscaled > /dev/null 2>&1 || true
        sleep 1
        sprite-env services create tailscaled \
            --cmd /usr/sbin/tailscaled \
            --args "--state=/var/lib/tailscale/tailscaled.state,--socket=/var/run/tailscale/tailscaled.sock" \
            --no-stream > /dev/null 2>&1

        # Wait for tailscaled
        for i in {1..10}; do
            if pgrep -x tailscaled > /dev/null; then break; fi
            sleep 1
        done
        info "tailscaled service created"
    elif command -v systemctl &> /dev/null; then
        substep "Starting tailscaled..."
        sudo systemctl enable --now tailscaled > /dev/null 2>&1
        info "tailscaled started"
    else
        substep "Starting tailscaled..."
        sudo tailscaled --state=/var/lib/tailscale/tailscaled.state > /dev/null 2>&1 &
        sleep 2
        info "tailscaled started"
    fi
}

# Authenticate Tailscale
auth_tailscale() {
    # Prompt for hostname first (will skip if already set or already unique)
    prompt_hostname

    if tailscale status > /dev/null 2>&1; then
        local current_name=$(tailscale status --json 2>/dev/null | jq -r '.Self.HostName // empty' 2>/dev/null)

        # Update hostname if we have a new one set
        if [ -n "$TS_HOSTNAME" ] && [ "$current_name" != "$TS_HOSTNAME" ]; then
            substep "Updating hostname to $TS_HOSTNAME..."
            sudo tailscale set --hostname="$TS_HOSTNAME" > /dev/null 2>&1 || true
            current_name="$TS_HOSTNAME"
        fi

        info "Tailscale authenticated as ${BOLD}${current_name:-$(hostname)}${NC}"
        return 0
    fi

    echo ""
    echo -e "  ${YELLOW}>>${NC} ${BOLD}Authenticate in your browser${NC}"
    echo ""

    # Include hostname in tailscale up if set
    if [ -n "$TS_HOSTNAME" ]; then
        sudo tailscale up --hostname="$TS_HOSTNAME" 2>&1 | grep -E "https://|Success" || true
    else
        sudo tailscale up 2>&1 | grep -E "https://|Success" || true
    fi

    local final_name=$(tailscale status --json 2>/dev/null | jq -r '.Self.HostName // empty' 2>/dev/null)
    echo ""
    info "Authenticated as ${BOLD}${final_name:-$(hostname)}${NC}"
}

# Set Tailscale operator
set_operator() {
    sudo tailscale set --operator="$USER" > /dev/null 2>&1 || true
}

# Get Tailscale IP
get_tailscale_ip() {
    tailscale ip -4 2>/dev/null || error "Failed to get Tailscale IP. Is Tailscale authenticated?"
}

# Install Syncthing
install_syncthing() {
    if command -v syncthing &> /dev/null; then
        info "Syncthing $(syncthing --version | head -1 | awk '{print $2}') installed"
        return 0
    fi

    substep "Installing Syncthing..."

    if [ "$OS" = "linux" ]; then
        # Add Syncthing apt repository
        if command -v apt-get &> /dev/null; then
            # Add the release PGP keys
            sudo mkdir -p /etc/apt/keyrings
            curl -fsSL https://syncthing.net/release-key.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/syncthing-archive-keyring.gpg 2>/dev/null

            # Add the stable channel repository
            echo "deb [signed-by=/etc/apt/keyrings/syncthing-archive-keyring.gpg] https://apt.syncthing.net/ syncthing stable" | \
                sudo tee /etc/apt/sources.list.d/syncthing.list > /dev/null

            sudo apt-get update -qq > /dev/null 2>&1
            sudo apt-get install -y -qq syncthing > /dev/null 2>&1
            info "Syncthing installed via apt"
        else
            error "apt not available. Please install Syncthing manually."
        fi
    elif [ "$OS" = "darwin" ]; then
        if command -v brew &> /dev/null; then
            brew install syncthing > /dev/null 2>&1
            info "Syncthing installed via brew"
        else
            error "Homebrew not available. Please install Syncthing manually."
        fi
    fi
}

# Generate initial Syncthing config if needed
init_syncthing_config() {
    if [ -f "$SYNCTHING_CONFIG_DIR/config.xml" ]; then
        return 0
    fi

    substep "Generating initial Syncthing config..."
    syncthing generate --config="$SYNCTHING_CONFIG_DIR" > /dev/null 2>&1
    info "Generated Syncthing config"
}

# Configure Syncthing for Tailscale-only access
configure_syncthing() {
    local ts_ip=$(get_tailscale_ip)
    local config_file="$SYNCTHING_CONFIG_DIR/config.xml"

    [ -f "$config_file" ] || error "Syncthing config not found at $config_file"

    substep "Configuring Syncthing for Tailscale..."

    # Backup original config
    cp "$config_file" "${config_file}.bak"

    # Configure using syncthing CLI if available, otherwise use xmllint
    if syncthing cli config options listen-addresses set "tcp://${ts_ip}:22000" > /dev/null 2>&1; then
        info "Set listen address to tcp://${ts_ip}:22000"
    else
        # Fallback to xmllint editing
        local tmp_config=$(mktemp)

        # Update listenAddress to only Tailscale IP
        xmllint --shell "$config_file" > /dev/null 2>&1 << EOF || true
cd //configuration/options/listenAddress
set tcp://${ts_ip}:22000
save $tmp_config
EOF

        if [ -s "$tmp_config" ]; then
            mv "$tmp_config" "$config_file"
            info "Set listen address to tcp://${ts_ip}:22000"
        else
            rm -f "$tmp_config"
            # Manual sed fallback
            sed -i "s|<listenAddress>.*</listenAddress>|<listenAddress>tcp://${ts_ip}:22000</listenAddress>|g" "$config_file"
            info "Set listen address to tcp://${ts_ip}:22000 (sed)"
        fi
    fi

    # Disable global discovery
    if syncthing cli config options global-announce-enabled set false > /dev/null 2>&1; then
        info "Disabled global discovery"
    else
        sed -i 's|<globalAnnounceEnabled>true</globalAnnounceEnabled>|<globalAnnounceEnabled>false</globalAnnounceEnabled>|g' "$config_file"
        info "Disabled global discovery (sed)"
    fi

    # Disable local discovery
    if syncthing cli config options local-announce-enabled set false > /dev/null 2>&1; then
        info "Disabled local discovery"
    else
        sed -i 's|<localAnnounceEnabled>true</localAnnounceEnabled>|<localAnnounceEnabled>false</localAnnounceEnabled>|g' "$config_file"
        info "Disabled local discovery (sed)"
    fi

    # Disable relays
    if syncthing cli config options relays-enabled set false > /dev/null 2>&1; then
        info "Disabled relays"
    else
        sed -i 's|<relaysEnabled>true</relaysEnabled>|<relaysEnabled>false</relaysEnabled>|g' "$config_file"
        info "Disabled relays (sed)"
    fi

    # Disable NAT traversal (not needed over Tailscale)
    if syncthing cli config options natenabled set false > /dev/null 2>&1; then
        info "Disabled NAT traversal"
    else
        sed -i 's|<natEnabled>true</natEnabled>|<natEnabled>false</natEnabled>|g' "$config_file"
        info "Disabled NAT traversal (sed)"
    fi

    # Keep GUI on localhost only
    if syncthing cli config gui raw-address set "127.0.0.1:8384" > /dev/null 2>&1; then
        info "GUI bound to 127.0.0.1:8384"
    else
        info "GUI already on localhost"
    fi
}

# Check if sprite-env has stop/start commands
sprite_env_has_stop() {
    sprite-env services --help 2>&1 | grep -q "stop <name>"
}

# Set up Syncthing as a service
setup_syncthing_service() {
    if is_sprite; then
        substep "Creating syncthing service..."

        local syncthing_path=$(which syncthing)
        if [ -z "$syncthing_path" ]; then
            error "syncthing not found in PATH"
        fi

        # Check if service already exists (any state)
        if sprite-env services list 2>/dev/null | jq -e '.[] | select(.name == "syncthing")' > /dev/null 2>&1; then
            if sprite_env_has_stop; then
                # New sprite-env: use stop/start
                sprite-env services stop syncthing > /dev/null 2>&1 || true
                sleep 1
                sprite-env services start syncthing > /dev/null 2>&1 || true
                sleep 2
                if sprite-env services list 2>/dev/null | jq -e '.[] | select(.name == "syncthing" and .state.status == "running")' > /dev/null 2>&1; then
                    info "syncthing service restarted"
                    return 0
                fi
            else
                # Old sprite-env: use signal + delete/create
                sprite-env services signal syncthing TERM > /dev/null 2>&1 || true
                sleep 2
            fi
            # Delete and recreate
            sprite-env services delete syncthing > /dev/null 2>&1 || true
            sleep 2
        fi

        # Create the service (without --needs for compatibility, tailscaled should already be running)
        sprite-env services create syncthing \
            --cmd "$syncthing_path" \
            --args "serve,--no-browser,--no-default-folder,--config=$SYNCTHING_CONFIG_DIR,--data=$SYNCTHING_CONFIG_DIR" \
            --no-stream > /dev/null 2>&1 || true

        # Verify service is actually running
        sleep 3
        if ! sprite-env services list 2>/dev/null | jq -e '.[] | select(.name == "syncthing" and .state.status == "running")' > /dev/null 2>&1; then
            error "syncthing service failed to start - check: sprite-env services list"
        fi
        info "syncthing service running"
    elif command -v systemctl &> /dev/null; then
        substep "Creating systemd service..."
        sudo tee /etc/systemd/system/syncthing@.service > /dev/null <<EOF
[Unit]
Description=Syncthing - Open Source Continuous File Synchronization for %i
Documentation=man:syncthing(1)
After=network.target tailscaled.service
Wants=tailscaled.service

[Service]
Type=simple
User=%i
ExecStart=$(which syncthing) serve --no-browser --no-default-folder
Restart=on-failure
RestartSec=5
SuccessExitStatus=3 4
RestartForceExitStatus=3 4

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl daemon-reload > /dev/null 2>&1
        sudo systemctl enable --now "syncthing@${USER}" > /dev/null 2>&1
        info "systemd service running"
    else
        warn "No service manager - run manually:"
        echo "    syncthing serve --no-browser"
    fi
}

# Set up spritesync discovery service
setup_spritesync_service() {
    if is_sprite; then
        substep "Creating spritesync service..."

        if [ ! -x "$INSTALL_DIR/spritesync" ]; then
            warn "spritesync binary not found at $INSTALL_DIR/spritesync - skipping service"
            return 0
        fi

        # Check if service already exists (any state)
        if sprite-env services list 2>/dev/null | jq -e '.[] | select(.name == "spritesync")' > /dev/null 2>&1; then
            if sprite_env_has_stop; then
                # New sprite-env: use stop/start
                sprite-env services stop spritesync > /dev/null 2>&1 || true
                sleep 1
                sprite-env services start spritesync > /dev/null 2>&1 || true
                sleep 2
                if sprite-env services list 2>/dev/null | jq -e '.[] | select(.name == "spritesync" and .state.status == "running")' > /dev/null 2>&1; then
                    info "spritesync discovery service restarted"
                    return 0
                fi
            else
                # Old sprite-env: use signal + delete/create
                sprite-env services signal spritesync TERM > /dev/null 2>&1 || true
                sleep 2
            fi
            # Delete and recreate
            sprite-env services delete spritesync > /dev/null 2>&1 || true
            sleep 2
        fi

        # Create the service (without --needs for compatibility, syncthing should already be running)
        sprite-env services create spritesync \
            --cmd "$INSTALL_DIR/spritesync" \
            --args "serve" \
            --no-stream > /dev/null 2>&1 || true

        # Verify service is actually running
        sleep 3
        if ! sprite-env services list 2>/dev/null | jq -e '.[] | select(.name == "spritesync" and .state.status == "running")' > /dev/null 2>&1; then
            error "spritesync service failed to start - check: sprite-env services list"
        fi
        info "spritesync discovery service running"
    elif command -v systemctl &> /dev/null; then
        substep "Creating spritesync systemd service..."
        sudo tee /etc/systemd/system/spritesync@.service > /dev/null <<EOF
[Unit]
Description=spritesync discovery service for %i
After=network.target syncthing@%i.service
Wants=syncthing@%i.service

[Service]
Type=simple
User=%i
ExecStart=$INSTALL_DIR/spritesync serve
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl daemon-reload > /dev/null 2>&1
        sudo systemctl enable --now "spritesync@${USER}" > /dev/null 2>&1
        info "spritesync systemd service running"
    else
        warn "No service manager - run manually:"
        echo "    spritesync serve"
    fi
}

# Get latest release version
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install spritesync binary
install_spritesync() {
    VERSION=$(get_latest_version)

    if [ -z "$VERSION" ]; then
        warn "No releases found - skipping binary install"
        warn "Build from source: go build -o spritesync"
        return 0
    fi

    substep "Downloading spritesync ${VERSION}..."
    curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/spritesync-${PLATFORM}" \
        -o /tmp/spritesync 2>/dev/null || {
        warn "Failed to download binary - skipping"
        return 0
    }

    chmod +x /tmp/spritesync
    sudo mv /tmp/spritesync "$INSTALL_DIR/spritesync"
    info "Installed spritesync ${VERSION}"
}

# Install Claude Code skill
install_skill() {
    # Create skills directory if it doesn't exist
    local skill_dir="$HOME/.claude/skills/spritesync"
    mkdir -p "$skill_dir"

    cat > "$skill_dir/SKILL.md" << 'SKILL_EOF'
---
name: spritesync
description: Use this skill when users want to sync directories between Sprite VMs using Syncthing over Tailscale. Use for syncing folders, checking sync status, discovering devices, or managing shared directories.
---

You help manage Syncthing-based directory synchronization between Sprite VMs over Tailscale.

## Mesh Sync (Recommended)

Create named sync groups that any device can join:

```bash
# On first Sprite - create the group
spritesync create myproject ~/code/myproject

# On every other Sprite - just join
spritesync join myproject
```

All devices in a group sync in a mesh (no single point of failure).

## Commands

### Mesh Sync
```bash
spritesync create <name> <dir>   # Create a named sync group
spritesync join <name>           # Join an existing sync group
spritesync groups                # List sync groups on this device
```

### Direct Sync (one-off between two devices)
```bash
spritesync sync ~/myproject <device-name>   # Sync with a specific device
spritesync unsync ~/myproject               # Stop syncing a directory
```

### Status & Discovery
```bash
spritesync status        # Show sync status of all folders
spritesync devices       # Discover spritesync devices on the tailnet
spritesync info          # Show this device's Syncthing ID and hostname
```

## Quick Actions

When user asks to:
- "create a sync" / "new sync group" -> `spritesync create <name> <dir>`
- "join sync" / "join group" -> `spritesync join <name>`
- "list groups" / "what groups" -> `spritesync groups`
- "sync status" / "what's syncing" -> `spritesync status`
- "find devices" / "list devices" -> `spritesync devices`
- "stop syncing" -> `spritesync unsync <folder>`

## How It Works

1. `create` makes a named sync group and registers it with the discovery service
2. `join` finds the group on the tailnet and connects to ALL existing members
3. All devices sync in a mesh - any device can go down without breaking sync
4. Tailnet membership = trust (no manual device approval needed)

## Troubleshooting

Check services:
```bash
sprite-env services get syncthing   # Syncthing service
sprite-env services get spritesync  # Discovery service
```

Verify Tailscale connection:
```bash
tailscale status
tailscale ping <device-name>
```
SKILL_EOF
    info "Claude Code skill installed"
}

# Main
main() {
    echo ""
    echo -e "${BOLD}  spritesync${NC} ${DIM}installer${NC}"
    echo ""

    step "Setting up environment"
    detect_platform
    info "Platform: ${PLATFORM}"
    install_deps

    step "Installing Tailscale"
    install_tailscale
    start_tailscaled

    step "Configuring Tailscale"
    auth_tailscale
    set_operator

    step "Installing Syncthing"
    install_syncthing
    init_syncthing_config
    configure_syncthing
    setup_syncthing_service

    step "Installing spritesync"
    install_spritesync
    setup_spritesync_service
    install_skill

    # Get device info for display
    local device_name=$(tailscale status --json 2>/dev/null | jq -r '.Self.HostName // empty' 2>/dev/null)
    device_name="${device_name:-$(hostname)}"
    local ts_ip=$(get_tailscale_ip)

    echo ""
    echo -e "${BOLD}  Done!${NC}"
    echo ""
    echo -e "  ${DIM}Device:${NC}     ${BOLD}${device_name}${NC}"
    echo -e "  ${DIM}Tailscale:${NC}  ${ts_ip}"
    echo -e "  ${DIM}Syncthing:${NC}  ${ts_ip}:22000"
    echo -e "  ${DIM}Discovery:${NC}  ${ts_ip}:8385"
    echo ""
    echo -e "  ${DIM}Quick Start:${NC}"
    echo -e "    ${BOLD}spritesync create skills ~/.claude/skills${NC}  # Create a sync group"
    echo -e "    ${BOLD}spritesync join skills${NC}                     # Join from other devices"
    echo ""
    echo -e "  ${DIM}Other Commands:${NC}"
    echo -e "    ${BOLD}spritesync devices${NC}    # Find other spritesync devices"
    echo -e "    ${BOLD}spritesync status${NC}     # Check sync status"
    echo -e "    ${BOLD}spritesync groups${NC}     # List sync groups"
    echo ""
}

main "$@"
