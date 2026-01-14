package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

// SyncGroup represents a named sync group that can be shared across devices
type SyncGroup struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	FolderID  string `json:"folder_id"`
	CreatedAt string `json:"created_at"`
}

// SyncGroupsConfig holds all sync groups for this device
type SyncGroupsConfig struct {
	Groups []SyncGroup `json:"groups"`
}

func getSyncGroupsPath() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "spritesync", "groups.json")
}

func loadSyncGroups() (*SyncGroupsConfig, error) {
	path := getSyncGroupsPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SyncGroupsConfig{Groups: []SyncGroup{}}, nil
		}
		return nil, err
	}
	var config SyncGroupsConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func saveSyncGroups(config *SyncGroupsConfig) error {
	path := getSyncGroupsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func generateGroupFolderID(groupName string) string {
	hash := sha256.Sum256([]byte(groupName))
	return fmt.Sprintf("spritesync-%x", hash[:8])
}

// SyncthingConfig represents the Syncthing configuration XML
type SyncthingConfig struct {
	XMLName xml.Name `xml:"configuration"`
	Folders []Folder `xml:"folder"`
	Devices []Device `xml:"device"`
	GUI     GUI      `xml:"gui"`
}

type Folder struct {
	ID     string `xml:"id,attr"`
	Label  string `xml:"label,attr"`
	Path   string `xml:"path,attr"`
	Paused bool   `xml:"paused,attr"`
}

type Device struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name,attr"`
}

type GUI struct {
	APIKey string `xml:"apikey"`
}

// FolderStatus from Syncthing REST API
type FolderStatus struct {
	State       string `json:"state"`
	GlobalFiles int    `json:"globalFiles"`
	LocalFiles  int    `json:"localFiles"`
	NeedFiles   int    `json:"needFiles"`
	Errors      int    `json:"errors"`
}

// StatusOutput for JSON output mode
type StatusOutput struct {
	Folders []FolderStatusOutput `json:"folders"`
}

type FolderStatusOutput struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Path   string `json:"path"`
	State  string `json:"state"`
	Paused bool   `json:"paused"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	// Handle version flag anywhere
	if cmd == "--version" || cmd == "-version" {
		fmt.Println(version)
		os.Exit(0)
	}

	switch cmd {
	case "serve":
		cmdServe(os.Args[2:])
	case "init":
		cmdInit(os.Args[2:])
	case "info":
		cmdInfo(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "devices":
		cmdDevices(os.Args[2:])
	case "create":
		cmdCreate(os.Args[2:])
	case "join":
		cmdJoin(os.Args[2:])
	case "sync":
		cmdSync(os.Args[2:])
	case "unsync":
		cmdUnsync(os.Args[2:])
	case "groups":
		cmdGroups(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("spritesync - Syncthing over Tailscale for Sprites")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  spritesync <command> [options]")
	fmt.Println()
	fmt.Println("Mesh Sync (recommended):")
	fmt.Println("  create     Create a named sync group")
	fmt.Println("  join       Join an existing sync group")
	fmt.Println("  groups     List sync groups on this device")
	fmt.Println()
	fmt.Println("Direct Sync:")
	fmt.Println("  sync       Sync a directory with a specific device")
	fmt.Println("  unsync     Remove a directory from sync")
	fmt.Println()
	fmt.Println("Other:")
	fmt.Println("  serve      Run discovery service (for sprite-env/systemd)")
	fmt.Println("  status     Show folder sync status")
	fmt.Println("  devices    List spritesync devices on tailnet")
	fmt.Println("  info       Show device information")
	fmt.Println("  version    Print version")
	fmt.Println("  help       Show this help")
	fmt.Println()
	fmt.Println("Quick Start:")
	fmt.Println("  # On first Sprite:")
	fmt.Println("  spritesync create skills ~/.claude/skills")
	fmt.Println()
	fmt.Println("  # On every new Sprite:")
	fmt.Println("  spritesync join skills")
	fmt.Println()
	fmt.Println("Use \"spritesync <command> --help\" for more information.")
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: spritesync init")
		fmt.Println()
		fmt.Println("Initialize spritesync configuration.")
		fmt.Println("Creates ~/.config/spritesync/apikey with a generated API key.")
	}
	fs.Parse(args)

	configDir := filepath.Join(os.Getenv("HOME"), ".config", "spritesync")
	apiKeyPath := filepath.Join(configDir, "apikey")

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	// Check if API key already exists
	if _, err := os.Stat(apiKeyPath); err == nil {
		fmt.Printf("Config already exists at %s\n", configDir)
		fmt.Println("Use the existing API key or delete it to regenerate.")
		return
	}

	// Generate a random API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating API key: %v\n", err)
		os.Exit(1)
	}
	apiKey := hex.EncodeToString(keyBytes)

	// Write API key to file
	if err := os.WriteFile(apiKeyPath, []byte(apiKey), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing API key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Initialized spritesync configuration at %s\n", configDir)
	fmt.Println("API key generated and stored.")
}

const discoveryPort = 8385

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: spritesync serve")
		fmt.Println()
		fmt.Println("Run the discovery service on the Tailscale interface.")
		fmt.Println("This allows other spritesync devices to discover and pair with this device.")
		fmt.Println()
		fmt.Println("The service listens on <tailscale-ip>:8385 and exposes:")
		fmt.Println("  /id      - Returns this device's Syncthing device ID")
		fmt.Println("  /health  - Health check endpoint")
	}
	fs.Parse(args)

	// Get Tailscale IP
	tsIP, err := getTailscaleIP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Tailscale IP: %v\n", err)
		fmt.Fprintln(os.Stderr, "Make sure Tailscale is running and connected.")
		os.Exit(1)
	}

	// Get our hostname for logging
	hostname, _ := getTailscaleHostname()

	// Set up HTTP handlers
	mux := http.NewServeMux()

	// /id - returns Syncthing device ID and hostname
	mux.HandleFunc("/id", func(w http.ResponseWriter, r *http.Request) {
		deviceID, err := getSyncthingDeviceID()
		if err != nil {
			http.Error(w, "Failed to get device ID", http.StatusInternalServerError)
			return
		}
		hostname, _ := getTailscaleHostname()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"device_id": deviceID,
			"hostname":  hostname,
		})
	})

	// /health - simple health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// /syncs - returns sync groups this device has
	mux.HandleFunc("/syncs", func(w http.ResponseWriter, r *http.Request) {
		groups, err := loadSyncGroups()
		if err != nil {
			http.Error(w, "Failed to load sync groups", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups.Groups)
	})

	// /register - allows a remote device to register itself with this device
	// This enables bidirectional sync when a new device joins a group
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			DeviceID string `json:"device_id"`
			Hostname string `json:"hostname"`
			IP       string `json:"ip"`
			FolderID string `json:"folder_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.DeviceID == "" || req.Hostname == "" || req.FolderID == "" {
			http.Error(w, "Missing required fields: device_id, hostname, folder_id", http.StatusBadRequest)
			return
		}

		// Check if we have this folder
		groups, err := loadSyncGroups()
		if err != nil {
			http.Error(w, "Failed to load sync groups", http.StatusInternalServerError)
			return
		}

		hasFolder := false
		for _, g := range groups.Groups {
			if g.FolderID == req.FolderID {
				hasFolder = true
				break
			}
		}

		if !hasFolder {
			http.Error(w, "Folder not found on this device", http.StatusNotFound)
			return
		}

		// Add the requesting device to our Syncthing config
		if err := addSyncthingDevice(req.DeviceID, req.Hostname, req.IP, true); err != nil {
			http.Error(w, fmt.Sprintf("Failed to add device: %v", err), http.StatusInternalServerError)
			return
		}

		// Share the folder with the requesting device
		cmd := exec.Command("syncthing", "cli", "config", "folders", req.FolderID, "devices", "add",
			"--device-id", req.DeviceID,
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			if !strings.Contains(string(output), "already exists") {
				http.Error(w, fmt.Sprintf("Failed to share folder: %s", string(output)), http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	})

	// Create server
	addr := fmt.Sprintf("%s:%d", tsIP, discoveryPort)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	fmt.Printf("spritesync discovery service starting\n")
	fmt.Printf("  Hostname: %s\n", hostname)
	fmt.Printf("  Listening: http://%s\n", addr)
	fmt.Println()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// getTailscaleIP returns this device's Tailscale IP address
func getTailscaleIP() (string, error) {
	cmd := exec.Command("tailscale", "ip", "-4")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Tailscale IP: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// getTailnetPeers returns all peers on the tailnet
func getTailnetPeers() ([]TailnetPeer, error) {
	cmd := exec.Command("tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get tailscale status: %w", err)
	}

	var status struct {
		Peer map[string]struct {
			HostName  string   `json:"HostName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
			Online    bool     `json:"Online"`
		} `json:"Peer"`
	}
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, fmt.Errorf("failed to parse tailscale status: %w", err)
	}

	var peers []TailnetPeer
	for _, peer := range status.Peer {
		if len(peer.TailscaleIPs) > 0 && peer.Online {
			peers = append(peers, TailnetPeer{
				Hostname: peer.HostName,
				IP:       peer.TailscaleIPs[0],
			})
		}
	}
	return peers, nil
}

type TailnetPeer struct {
	Hostname string
	IP       string
}

// discoverDevice queries a peer for its Syncthing device ID
func discoverDevice(peer TailnetPeer) (*DiscoveredDevice, error) {
	url := fmt.Sprintf("http://%s:%d/id", peer.IP, discoveryPort)

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		DeviceID string `json:"device_id"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &DiscoveredDevice{
		Hostname: result.Hostname,
		IP:       peer.IP,
		DeviceID: result.DeviceID,
	}, nil
}

type DiscoveredDevice struct {
	Hostname string
	IP       string
	DeviceID string
}

// discoverAllDevices scans the tailnet for spritesync devices
func discoverAllDevices() ([]DiscoveredDevice, error) {
	peers, err := getTailnetPeers()
	if err != nil {
		return nil, err
	}

	var discovered []DiscoveredDevice
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, peer := range peers {
		wg.Add(1)
		go func(p TailnetPeer) {
			defer wg.Done()
			device, err := discoverDevice(p)
			if err == nil {
				mu.Lock()
				discovered = append(discovered, *device)
				mu.Unlock()
			}
		}(peer)
	}

	wg.Wait()
	return discovered, nil
}

// discoverDeviceByName finds a specific device on the tailnet
// If multiple devices have the same hostname, returns the first one that responds
func discoverDeviceByName(name string) (*DiscoveredDevice, error) {
	peers, err := getTailnetPeers()
	if err != nil {
		return nil, err
	}

	nameLower := strings.ToLower(name)
	var lastErr error
	var matchCount int

	for _, peer := range peers {
		if strings.ToLower(peer.Hostname) == nameLower {
			matchCount++
			device, err := discoverDevice(peer)
			if err == nil {
				return device, nil
			}
			lastErr = err
		}
	}

	if matchCount == 0 {
		return nil, fmt.Errorf("device '%s' not found on tailnet", name)
	}

	return nil, fmt.Errorf("device '%s' found but not responding: %v", name, lastErr)
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: spritesync info")
		fmt.Println()
		fmt.Println("Show this device's Syncthing device ID and Tailscale hostname.")
	}
	fs.Parse(args)

	// Get Syncthing device ID
	deviceID, err := getSyncthingDeviceID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Syncthing device ID: %v\n", err)
		os.Exit(1)
	}

	// Get Tailscale hostname
	hostname, err := getTailscaleHostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Tailscale hostname: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Syncthing Device ID: %s\n", deviceID)
	fmt.Printf("Tailscale Hostname:  %s\n", hostname)
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	fs.Usage = func() {
		fmt.Println("Usage: spritesync status [--json]")
		fmt.Println()
		fmt.Println("Show folder sync status from Syncthing.")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --json    Output in JSON format")
	}
	fs.Parse(args)

	apiKey, err := getSyncthingAPIKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Syncthing API key: %v\n", err)
		os.Exit(1)
	}

	folders, err := getSyncthingFolders()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Syncthing folders: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		output := StatusOutput{Folders: []FolderStatusOutput{}}
		for _, folder := range folders {
			status, err := getFolderStatus(apiKey, folder.ID)
			state := "unknown"
			if err == nil {
				state = status.State
			}
			output.Folders = append(output.Folders, FolderStatusOutput{
				ID:     folder.ID,
				Label:  folder.Label,
				Path:   folder.Path,
				State:  state,
				Paused: folder.Paused,
			})
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(jsonBytes))
	} else {
		if len(folders) == 0 {
			fmt.Println("No folders configured for sync.")
			return
		}

		fmt.Println("Folder Status:")
		fmt.Println()
		for _, folder := range folders {
			label := folder.Label
			if label == "" {
				label = folder.ID
			}
			status, err := getFolderStatus(apiKey, folder.ID)
			state := "unknown"
			if err == nil {
				state = status.State
			}
			if folder.Paused {
				state = "paused"
			}
			fmt.Printf("  %s\n", label)
			fmt.Printf("    Path:   %s\n", folder.Path)
			fmt.Printf("    Status: %s\n", state)
			fmt.Println()
		}
	}
}

func getSyncthingDeviceID() (string, error) {
	// First try to get from running Syncthing via CLI
	cmd := exec.Command("syncthing", "cli", "show", "system")
	output, err := cmd.Output()
	if err == nil {
		var result struct {
			MyID string `json:"myID"`
		}
		if json.Unmarshal(output, &result) == nil && result.MyID != "" {
			return result.MyID, nil
		}
	}

	// Fallback: try REST API
	apiKey, err := getSyncthingAPIKey()
	if err == nil {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:8384/rest/system/status", nil)
		req.Header.Set("X-API-Key", apiKey)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var result struct {
				MyID string `json:"myID"`
			}
			if json.NewDecoder(resp.Body).Decode(&result) == nil && result.MyID != "" {
				return result.MyID, nil
			}
		}
	}

	// Last fallback: parse config.xml
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "syncthing", "config.xml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("cannot read Syncthing config: %w", err)
	}

	var config SyncthingConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("cannot parse Syncthing config: %w", err)
	}

	// Find the local device (first one typically)
	if len(config.Devices) > 0 {
		return config.Devices[0].ID, nil
	}

	return "", fmt.Errorf("no device ID found in Syncthing config")
}

func getTailscaleHostname() (string, error) {
	cmd := exec.Command("tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run tailscale status: %w", err)
	}

	var status struct {
		Self struct {
			HostName string `json:"HostName"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(output, &status); err != nil {
		return "", fmt.Errorf("failed to parse tailscale status: %w", err)
	}

	if status.Self.HostName == "" {
		// Fallback to regular hostname
		hostname, err := os.Hostname()
		if err != nil {
			return "", err
		}
		return hostname, nil
	}

	return status.Self.HostName, nil
}

func getSyncthingAPIKey() (string, error) {
	// First check if Syncthing is running and get key from config
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "syncthing", "config.xml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("cannot read Syncthing config: %w", err)
	}

	var config SyncthingConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("cannot parse Syncthing config: %w", err)
	}

	if config.GUI.APIKey != "" {
		return config.GUI.APIKey, nil
	}

	return "", fmt.Errorf("no API key found in Syncthing config")
}

func getSyncthingFolders() ([]Folder, error) {
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "syncthing", "config.xml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read Syncthing config: %w", err)
	}

	var config SyncthingConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("cannot parse Syncthing config: %w", err)
	}

	return config.Folders, nil
}

func getFolderStatus(apiKey, folderID string) (*FolderStatus, error) {
	url := fmt.Sprintf("http://127.0.0.1:8384/rest/db/status?folder=%s", folderID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var status FolderStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}

	return &status, nil
}

func cmdDevices(args []string) {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	fs.Usage = func() {
		fmt.Println("Usage: spritesync devices [--json]")
		fmt.Println()
		fmt.Println("Discover spritesync devices on the tailnet.")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --json    Output in JSON format")
	}
	fs.Parse(args)

	fmt.Println("Scanning tailnet for spritesync devices...")
	devices, err := discoverAllDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error discovering devices: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		type DeviceOutput struct {
			Hostname string `json:"hostname"`
			IP       string `json:"ip"`
			DeviceID string `json:"device_id"`
		}
		type DevicesOutput struct {
			Devices []DeviceOutput `json:"devices"`
		}
		output := DevicesOutput{Devices: []DeviceOutput{}}
		for _, d := range devices {
			output.Devices = append(output.Devices, DeviceOutput{
				Hostname: d.Hostname,
				IP:       d.IP,
				DeviceID: d.DeviceID,
			})
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(jsonBytes))
	} else {
		if len(devices) == 0 {
			fmt.Println("No spritesync devices found on tailnet.")
			fmt.Println("Make sure other devices are running 'spritesync serve'.")
			return
		}

		fmt.Printf("Found %d spritesync device(s):\n\n", len(devices))
		for _, d := range devices {
			fmt.Printf("  %s\n", d.Hostname)
			fmt.Printf("    IP: %s\n", d.IP)
			fmt.Printf("    Device ID: %s...%s\n", d.DeviceID[:7], d.DeviceID[len(d.DeviceID)-7:])
			fmt.Println()
		}
	}
}

func getSyncthingDevices() ([]Device, error) {
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "syncthing", "config.xml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read Syncthing config: %w", err)
	}

	var config SyncthingConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("cannot parse Syncthing config: %w", err)
	}

	return config.Devices, nil
}

func addSyncthingDevice(deviceID, name, address string, autoAccept bool) error {
	// Use syncthing CLI to add the device
	cmd := exec.Command("syncthing", "cli", "config", "devices", "add",
		"--device-id", deviceID,
		"--name", name,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Device might already exist, try to update it
		if strings.Contains(string(output), "already exists") {
			// Update the existing device name
			cmd = exec.Command("syncthing", "cli", "config", "devices", deviceID, "name", "set", name)
			cmd.Run()
		} else {
			return fmt.Errorf("failed to add device: %s", string(output))
		}
	}

	// Set the device address (critical for connectivity when discovery is disabled)
	if address != "" {
		tcpAddr := fmt.Sprintf("tcp://%s:22000", address)
		cmd = exec.Command("syncthing", "cli", "config", "devices", deviceID, "addresses", "add", tcpAddr)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Address might already exist, which is fine
			if !strings.Contains(string(output), "already exists") {
				return fmt.Errorf("failed to set device address: %s", string(output))
			}
		}
	}

	// Enable auto-accept folders if requested
	if autoAccept {
		cmd = exec.Command("syncthing", "cli", "config", "devices", deviceID, "auto-accept-folders", "set", "true")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to enable auto-accept: %s", string(output))
		}
	}

	return nil
}

func cmdSync(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: spritesync sync <directory> <device>")
		fmt.Println()
		fmt.Println("Sync a directory with another device.")
		fmt.Println("Automatically discovers and pairs with the target device.")
		fmt.Println()
		fmt.Println("The folder ID is deterministic based on the directory path and hostnames,")
		fmt.Println("so the same sync can be re-established after reconnection.")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  spritesync sync ~/projects my-other-sprite")
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "Error: directory and device required")
		fs.Usage()
		os.Exit(1)
	}

	directory := fs.Arg(0)
	targetDevice := fs.Arg(1)

	// Expand ~ to home directory
	if strings.HasPrefix(directory, "~") {
		home := os.Getenv("HOME")
		directory = filepath.Join(home, directory[1:])
	}

	// Get absolute path
	absPath, err := filepath.Abs(directory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving directory path: %v\n", err)
		os.Exit(1)
	}

	// Check if directory exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: directory does not exist: %s\n", absPath)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error accessing directory: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: %s is not a directory\n", absPath)
		os.Exit(1)
	}

	// Auto-discover the target device
	fmt.Printf("Discovering %s...\n", targetDevice)
	discovered, err := discoverDeviceByName(targetDevice)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Make sure the target device is running 'spritesync serve'.")
		os.Exit(1)
	}

	fmt.Printf("Found %s (ID: %s...%s)\n", discovered.Hostname,
		discovered.DeviceID[:7], discovered.DeviceID[len(discovered.DeviceID)-7:])

	// Auto-pair: add device to Syncthing with autoAcceptFolders and address
	fmt.Printf("Pairing with %s (%s)...\n", discovered.Hostname, discovered.IP)
	if err := addSyncthingDevice(discovered.DeviceID, discovered.Hostname, discovered.IP, true); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding device: %v\n", err)
		os.Exit(1)
	}

	// Get our hostname for deterministic folder ID
	myHostname, err := getTailscaleHostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting hostname: %v\n", err)
		os.Exit(1)
	}

	// Generate deterministic folder ID from path and hostnames
	folderID := generateFolderID(absPath, myHostname, discovered.Hostname)
	folderLabel := filepath.Base(absPath)

	// Add the folder to Syncthing
	fmt.Printf("Creating sync folder...\n")
	if err := addSyncthingFolder(folderID, folderLabel, absPath, discovered.DeviceID); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding folder to Syncthing: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("Syncing %s with %s\n", absPath, discovered.Hostname)
	fmt.Printf("Folder ID: %s\n", folderID)
	fmt.Println()
	fmt.Println("The remote device will auto-accept this folder.")
	fmt.Println("Use 'spritesync status' to check sync progress.")
}

func cmdUnsync(args []string) {
	fs := flag.NewFlagSet("unsync", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: spritesync unsync <directory>")
		fmt.Println()
		fmt.Println("Remove a directory from sync.")
		fmt.Println("This removes the folder from Syncthing but does not delete any files.")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  spritesync unsync ~/projects")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: directory required")
		fs.Usage()
		os.Exit(1)
	}

	directory := fs.Arg(0)

	// Expand ~ to home directory
	if strings.HasPrefix(directory, "~") {
		home := os.Getenv("HOME")
		directory = filepath.Join(home, directory[1:])
	}

	// Get absolute path
	absPath, err := filepath.Abs(directory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving directory path: %v\n", err)
		os.Exit(1)
	}

	// Find folder in Syncthing config by path
	folders, err := getSyncthingFolders()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting folders: %v\n", err)
		os.Exit(1)
	}

	var folderID string
	for _, f := range folders {
		if f.Path == absPath {
			folderID = f.ID
			break
		}
	}

	if folderID == "" {
		fmt.Fprintf(os.Stderr, "Error: directory %s is not being synced\n", absPath)
		os.Exit(1)
	}

	// Remove the folder from Syncthing
	if err := removeSyncthingFolder(folderID); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing folder from Syncthing: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Stopped syncing %s\n", absPath)
	fmt.Println("Files have not been deleted.")
}

// generateFolderID creates a deterministic folder ID from path and hostnames
// The ID is the same regardless of which device initiates the sync
func generateFolderID(path, hostname1, hostname2 string) string {
	// Sort hostnames to ensure deterministic ID
	hosts := []string{hostname1, hostname2}
	if hosts[0] > hosts[1] {
		hosts[0], hosts[1] = hosts[1], hosts[0]
	}

	// Create hash from sorted hostnames and path
	input := fmt.Sprintf("%s:%s:%s", path, hosts[0], hosts[1])
	hash := sha256.Sum256([]byte(input))
	// Use first 8 bytes for a shorter but still unique ID
	return fmt.Sprintf("spritesync-%x", hash[:8])
}

// getDeviceIDByName looks up a device ID by its name
func getDeviceIDByName(name string) (string, error) {
	devices, err := getSyncthingDevices()
	if err != nil {
		return "", err
	}

	// Check exact match first
	for _, d := range devices {
		if d.Name == name {
			return d.ID, nil
		}
	}

	// Check case-insensitive match
	nameLower := strings.ToLower(name)
	for _, d := range devices {
		if strings.ToLower(d.Name) == nameLower {
			return d.ID, nil
		}
	}

	return "", fmt.Errorf("device not found: %s", name)
}

// addSyncthingFolder adds a folder to Syncthing and shares it with a device
func addSyncthingFolder(folderID, label, path, deviceID string) error {
	// Use syncthing CLI to add the folder
	cmd := exec.Command("syncthing", "cli", "config", "folders", "add",
		"--id", folderID,
		"--label", label,
		"--path", path,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Folder might already exist
		if !strings.Contains(string(output), "already exists") {
			return fmt.Errorf("failed to add folder: %s", string(output))
		}
	}

	// Share the folder with the device
	cmd = exec.Command("syncthing", "cli", "config", "folders", folderID, "devices", "add",
		"--device-id", deviceID,
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		// Device might already be shared
		if !strings.Contains(string(output), "already exists") {
			return fmt.Errorf("failed to share folder with device: %s", string(output))
		}
	}

	return nil
}

// removeSyncthingFolder removes a folder from Syncthing
func removeSyncthingFolder(folderID string) error {
	cmd := exec.Command("syncthing", "cli", "config", "folders", "remove",
		"--id", folderID,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove folder: %s", string(output))
	}
	return nil
}

func cmdCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: spritesync create <name> <directory>")
		fmt.Println()
		fmt.Println("Create a named sync group that other devices can join.")
		fmt.Println("All devices that join the same group will sync in a mesh.")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  spritesync create skills ~/.claude/skills")
		fmt.Println()
		fmt.Println("Then on other devices:")
		fmt.Println("  spritesync join skills")
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "Error: name and directory required")
		fs.Usage()
		os.Exit(1)
	}

	groupName := fs.Arg(0)
	directory := fs.Arg(1)

	// Validate group name (alphanumeric and dashes only)
	for _, c := range groupName {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			fmt.Fprintf(os.Stderr, "Error: group name can only contain letters, numbers, dashes, and underscores\n")
			os.Exit(1)
		}
	}

	// Expand ~ to home directory
	if strings.HasPrefix(directory, "~") {
		home := os.Getenv("HOME")
		directory = filepath.Join(home, directory[1:])
	}

	// Get absolute path
	absPath, err := filepath.Abs(directory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving directory path: %v\n", err)
		os.Exit(1)
	}

	// Check if directory exists, create if not
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Creating directory %s...\n", absPath)
			if err := os.MkdirAll(absPath, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error accessing directory: %v\n", err)
			os.Exit(1)
		}
	} else if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: %s is not a directory\n", absPath)
		os.Exit(1)
	}

	// Check if group already exists locally
	groups, err := loadSyncGroups()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading sync groups: %v\n", err)
		os.Exit(1)
	}

	for _, g := range groups.Groups {
		if g.Name == groupName {
			fmt.Fprintf(os.Stderr, "Error: group '%s' already exists on this device\n", groupName)
			fmt.Fprintf(os.Stderr, "Path: %s\n", g.Path)
			os.Exit(1)
		}
	}

	// Generate folder ID from group name
	folderID := generateGroupFolderID(groupName)

	// Create the folder in Syncthing
	fmt.Printf("Creating sync group '%s'...\n", groupName)
	cmd := exec.Command("syncthing", "cli", "config", "folders", "add",
		"--id", folderID,
		"--label", groupName,
		"--path", absPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "already exists") {
			fmt.Fprintf(os.Stderr, "Error creating folder in Syncthing: %s\n", string(output))
			os.Exit(1)
		}
	}

	// Save group to local config
	group := SyncGroup{
		Name:      groupName,
		Path:      absPath,
		FolderID:  folderID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	groups.Groups = append(groups.Groups, group)
	if err := saveSyncGroups(groups); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving sync groups: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("Created sync group: %s\n", groupName)
	fmt.Printf("  Path:      %s\n", absPath)
	fmt.Printf("  Folder ID: %s\n", folderID)
	fmt.Println()
	fmt.Println("Other devices can now join with:")
	fmt.Printf("  spritesync join %s\n", groupName)
}

func cmdJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	pathFlag := fs.String("path", "", "Override the local path (default: same as creator)")
	fs.Usage = func() {
		fmt.Println("Usage: spritesync join <name> [--path <directory>]")
		fmt.Println()
		fmt.Println("Join an existing sync group created on another device.")
		fmt.Println("Automatically discovers the group and syncs with all members.")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --path    Use a different local path than the group creator")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  spritesync join skills")
		fmt.Println("  spritesync join skills --path ~/my-skills")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: group name required")
		fs.Usage()
		os.Exit(1)
	}

	groupName := fs.Arg(0)

	// Check if we already have this group
	groups, err := loadSyncGroups()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading sync groups: %v\n", err)
		os.Exit(1)
	}

	for _, g := range groups.Groups {
		if g.Name == groupName {
			fmt.Fprintf(os.Stderr, "Error: already a member of group '%s'\n", groupName)
			fmt.Fprintf(os.Stderr, "Path: %s\n", g.Path)
			os.Exit(1)
		}
	}

	// Discover devices and find one with this group
	fmt.Printf("Searching for group '%s' on tailnet...\n", groupName)

	devices, err := discoverAllDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error discovering devices: %v\n", err)
		os.Exit(1)
	}

	if len(devices) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no spritesync devices found on tailnet")
		os.Exit(1)
	}

	// Query each device for the group
	var foundGroup *SyncGroup
	var foundDevice *DiscoveredDevice

	for _, device := range devices {
		deviceGroups, err := getDeviceSyncGroups(device)
		if err != nil {
			continue
		}
		for _, g := range deviceGroups {
			if g.Name == groupName {
				foundGroup = &g
				foundDevice = &device
				break
			}
		}
		if foundGroup != nil {
			break
		}
	}

	if foundGroup == nil {
		fmt.Fprintf(os.Stderr, "Error: group '%s' not found on any device\n", groupName)
		fmt.Fprintln(os.Stderr, "Make sure another device has created this group with:")
		fmt.Fprintf(os.Stderr, "  spritesync create %s <directory>\n", groupName)
		os.Exit(1)
	}

	fmt.Printf("Found group '%s' on %s\n", groupName, foundDevice.Hostname)

	// Determine local path
	localPath := foundGroup.Path
	if *pathFlag != "" {
		if strings.HasPrefix(*pathFlag, "~") {
			home := os.Getenv("HOME")
			localPath = filepath.Join(home, (*pathFlag)[1:])
		} else {
			localPath, _ = filepath.Abs(*pathFlag)
		}
	}

	// Create directory if it doesn't exist
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		fmt.Printf("Creating directory %s...\n", localPath)
		if err := os.MkdirAll(localPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Get our own device info for registration
	myDeviceID, err := getSyncthingDeviceID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting device ID: %v\n", err)
		os.Exit(1)
	}
	myHostname, err := getTailscaleHostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting hostname: %v\n", err)
		os.Exit(1)
	}
	myIP, err := getTailscaleIP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Tailscale IP: %v\n", err)
		os.Exit(1)
	}

	// Add the founding device to Syncthing
	fmt.Printf("Adding device %s...\n", foundDevice.Hostname)
	if err := addSyncthingDevice(foundDevice.DeviceID, foundDevice.Hostname, foundDevice.IP, true); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding device: %v\n", err)
		os.Exit(1)
	}

	// Create the folder in Syncthing with the same folder ID
	fmt.Printf("Creating sync folder...\n")
	cmd := exec.Command("syncthing", "cli", "config", "folders", "add",
		"--id", foundGroup.FolderID,
		"--label", groupName,
		"--path", localPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "already exists") {
			fmt.Fprintf(os.Stderr, "Error creating folder: %s\n", string(output))
			os.Exit(1)
		}
	}

	// Share the folder with the founding device
	cmd = exec.Command("syncthing", "cli", "config", "folders", foundGroup.FolderID, "devices", "add",
		"--device-id", foundDevice.DeviceID,
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "already exists") {
			fmt.Fprintf(os.Stderr, "Error sharing folder: %s\n", string(output))
			os.Exit(1)
		}
	}

	// Register ourselves with the founding device so it adds us to its config
	fmt.Printf("Registering with %s...\n", foundDevice.Hostname)
	if err := registerWithDevice(*foundDevice, myDeviceID, myHostname, myIP, foundGroup.FolderID); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to register with %s: %v\n", foundDevice.Hostname, err)
		fmt.Fprintln(os.Stderr, "The remote device may need to be updated to support registration.")
	}

	// Now discover and add ALL devices that have this group
	fmt.Println("Connecting to other group members...")
	memberCount := 1 // counting the first device we found

	for _, device := range devices {
		if device.DeviceID == foundDevice.DeviceID {
			continue // already added
		}

		deviceGroups, err := getDeviceSyncGroups(device)
		if err != nil {
			continue
		}

		hasGroup := false
		for _, g := range deviceGroups {
			if g.Name == groupName {
				hasGroup = true
				break
			}
		}

		if hasGroup {
			// Add this device too
			if err := addSyncthingDevice(device.DeviceID, device.Hostname, device.IP, true); err == nil {
				cmd = exec.Command("syncthing", "cli", "config", "folders", foundGroup.FolderID, "devices", "add",
					"--device-id", device.DeviceID,
				)
				cmd.Run()
				// Register ourselves with this device too
				registerWithDevice(device, myDeviceID, myHostname, myIP, foundGroup.FolderID)
				memberCount++
				fmt.Printf("  + %s\n", device.Hostname)
			}
		}
	}

	// Save group to local config
	group := SyncGroup{
		Name:      groupName,
		Path:      localPath,
		FolderID:  foundGroup.FolderID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	groups.Groups = append(groups.Groups, group)
	if err := saveSyncGroups(groups); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving sync groups: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("Joined sync group: %s\n", groupName)
	fmt.Printf("  Path:    %s\n", localPath)
	fmt.Printf("  Members: %d device(s)\n", memberCount)
	fmt.Println()
	fmt.Println("Files will sync automatically. Use 'spritesync status' to check progress.")
}

// registerWithDevice registers this device with a remote device for a specific folder
// This enables bidirectional sync by having the remote device add us to its config
func registerWithDevice(device DiscoveredDevice, myDeviceID, myHostname, myIP, folderID string) error {
	url := fmt.Sprintf("http://%s:%d/register", device.IP, discoveryPort)

	reqBody := struct {
		DeviceID string `json:"device_id"`
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		FolderID string `json:"folder_id"`
	}{
		DeviceID: myDeviceID,
		Hostname: myHostname,
		IP:       myIP,
		FolderID: folderID,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s", strings.TrimSpace(string(body)))
	}

	return nil
}

// getDeviceSyncGroups queries a device for its sync groups
func getDeviceSyncGroups(device DiscoveredDevice) ([]SyncGroup, error) {
	url := fmt.Sprintf("http://%s:%d/syncs", device.IP, discoveryPort)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var groups []SyncGroup
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, err
	}

	return groups, nil
}

func cmdGroups(args []string) {
	fs := flag.NewFlagSet("groups", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	fs.Usage = func() {
		fmt.Println("Usage: spritesync groups [--json]")
		fmt.Println()
		fmt.Println("List sync groups on this device.")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --json    Output in JSON format")
	}
	fs.Parse(args)

	groups, err := loadSyncGroups()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading sync groups: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		jsonBytes, _ := json.MarshalIndent(groups.Groups, "", "  ")
		fmt.Println(string(jsonBytes))
		return
	}

	if len(groups.Groups) == 0 {
		fmt.Println("No sync groups configured.")
		fmt.Println()
		fmt.Println("Create one with:")
		fmt.Println("  spritesync create <name> <directory>")
		fmt.Println()
		fmt.Println("Or join an existing group:")
		fmt.Println("  spritesync join <name>")
		return
	}

	fmt.Println("Sync Groups:")
	fmt.Println()
	for _, g := range groups.Groups {
		fmt.Printf("  %s\n", g.Name)
		fmt.Printf("    Path:      %s\n", g.Path)
		fmt.Printf("    Folder ID: %s\n", g.FolderID)
		fmt.Println()
	}
}
