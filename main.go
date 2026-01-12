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
	case "sync":
		cmdSync(os.Args[2:])
	case "unsync":
		cmdUnsync(os.Args[2:])
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
	fmt.Println("Commands:")
	fmt.Println("  serve      Run discovery service (for sprite-env/systemd)")
	fmt.Println("  init       Initialize configuration and API key")
	fmt.Println("  info       Show device information")
	fmt.Println("  status     Show folder sync status")
	fmt.Println("  devices    List spritesync devices on tailnet")
	fmt.Println("  sync       Sync a directory with another device")
	fmt.Println("  unsync     Remove a directory from sync")
	fmt.Println("  version    Print version")
	fmt.Println("  help       Show this help")
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

func addSyncthingDevice(deviceID, name string, autoAccept bool) error {
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

	// Auto-pair: add device to Syncthing with autoAcceptFolders
	fmt.Printf("Pairing with %s...\n", discovered.Hostname)
	if err := addSyncthingDevice(discovered.DeviceID, discovered.Hostname, true); err != nil {
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
