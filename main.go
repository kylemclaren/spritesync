package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	case "init":
		cmdInit(os.Args[2:])
	case "info":
		cmdInfo(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "pair":
		cmdPair(os.Args[2:])
	case "devices":
		cmdDevices(os.Args[2:])
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
	fmt.Println("  init       Initialize configuration and API key")
	fmt.Println("  info       Show device information")
	fmt.Println("  status     Show folder sync status")
	fmt.Println("  pair       Pair with another device")
	fmt.Println("  devices    List paired devices")
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

func cmdPair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Minute, "Timeout waiting for pairing response")
	fs.Usage = func() {
		fmt.Println("Usage: spritesync pair <device>")
		fmt.Println()
		fmt.Println("Pair with another device by exchanging Syncthing device IDs via Taildrop.")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --timeout    Timeout waiting for response (default: 5m)")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println("  spritesync pair my-other-sprite")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: device name required")
		fs.Usage()
		os.Exit(1)
	}

	targetDevice := fs.Arg(0)

	// Get our Syncthing device ID
	myDeviceID, err := getSyncthingDeviceID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Syncthing device ID: %v\n", err)
		os.Exit(1)
	}

	// Get our hostname for the pairing file
	myHostname, err := getTailscaleHostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting hostname: %v\n", err)
		os.Exit(1)
	}

	// Create temp file with our device info
	tmpDir := os.TempDir()
	pairFile := filepath.Join(tmpDir, fmt.Sprintf("spritesync-pair-%s.txt", myHostname))

	content := fmt.Sprintf("%s\n%s\n", myDeviceID, myHostname)
	if err := os.WriteFile(pairFile, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing pair file: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(pairFile)

	fmt.Printf("Sending device ID to %s...\n", targetDevice)

	// Send our device ID via Taildrop
	cmd := exec.Command("tailscale", "file", "cp", pairFile, targetDevice+":")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending device ID: %v\n%s\n", err, string(output))
		os.Exit(1)
	}

	fmt.Println("Device ID sent. Waiting for partner's device ID...")
	fmt.Println("(The other device should also run 'spritesync pair' with your hostname)")

	// Wait to receive partner's device ID
	inboxDir := filepath.Join(tmpDir, "spritesync-inbox")
	if err := os.MkdirAll(inboxDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating inbox directory: %v\n", err)
		os.Exit(1)
	}

	// Start receiving files in background
	deadline := time.Now().Add(*timeout)
	var partnerDeviceID, partnerHostname string

	for time.Now().Before(deadline) {
		// Check for received pairing files
		matches, _ := filepath.Glob(filepath.Join(inboxDir, "spritesync-pair-*.txt"))
		for _, match := range matches {
			// Read the pairing file
			data, err := os.ReadFile(match)
			if err != nil {
				continue
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) >= 2 {
				partnerDeviceID = strings.TrimSpace(lines[0])
				partnerHostname = strings.TrimSpace(lines[1])
				// Remove the processed file
				os.Remove(match)
				break
			}
		}

		if partnerDeviceID != "" {
			break
		}

		// Try to receive files non-blocking
		cmd := exec.Command("tailscale", "file", "get", "--wait=1s", inboxDir)
		cmd.Run() // Ignore errors, just polling

		time.Sleep(2 * time.Second)
	}

	if partnerDeviceID == "" {
		fmt.Fprintln(os.Stderr, "Timeout waiting for partner's device ID")
		fmt.Fprintln(os.Stderr, "Make sure the other device runs: spritesync pair "+myHostname)
		os.Exit(1)
	}

	fmt.Printf("Received device ID from %s\n", partnerHostname)

	// Add partner device to Syncthing with autoAcceptFolders
	if err := addSyncthingDevice(partnerDeviceID, partnerHostname, true); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding device to Syncthing: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully paired with %s!\n", partnerHostname)
	fmt.Println("Devices will auto-accept shared folders from each other.")
}

func cmdDevices(args []string) {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	fs.Usage = func() {
		fmt.Println("Usage: spritesync devices [--json]")
		fmt.Println()
		fmt.Println("List all paired devices.")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --json    Output in JSON format")
	}
	fs.Parse(args)

	devices, err := getSyncthingDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting devices: %v\n", err)
		os.Exit(1)
	}

	// Get our own device ID to filter it out
	myDeviceID, _ := getSyncthingDeviceID()

	// Filter out our own device
	var pairedDevices []Device
	for _, d := range devices {
		if d.ID != myDeviceID {
			pairedDevices = append(pairedDevices, d)
		}
	}

	if *jsonOutput {
		type DeviceOutput struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		type DevicesOutput struct {
			Devices []DeviceOutput `json:"devices"`
		}
		output := DevicesOutput{Devices: []DeviceOutput{}}
		for _, d := range pairedDevices {
			output.Devices = append(output.Devices, DeviceOutput{
				ID:   d.ID,
				Name: d.Name,
			})
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(jsonBytes))
	} else {
		if len(pairedDevices) == 0 {
			fmt.Println("No paired devices.")
			fmt.Println("Use 'spritesync pair <device>' to pair with another device.")
			return
		}

		fmt.Println("Paired Devices:")
		fmt.Println()
		for _, d := range pairedDevices {
			name := d.Name
			if name == "" {
				name = "(unnamed)"
			}
			fmt.Printf("  %s\n", name)
			fmt.Printf("    ID: %s\n", d.ID)
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

// waitForPairFile polls the inbox directory for a pairing file from the target
func waitForPairFile(inboxDir string, timeout time.Duration) (deviceID, hostname string, err error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Check for received pairing files
		matches, _ := filepath.Glob(filepath.Join(inboxDir, "spritesync-pair-*.txt"))
		for _, match := range matches {
			data, err := os.ReadFile(match)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}

			if len(lines) >= 2 {
				deviceID = strings.TrimSpace(lines[0])
				hostname = strings.TrimSpace(lines[1])
				os.Remove(match) // Clean up
				return deviceID, hostname, nil
			}
		}

		time.Sleep(time.Second)
	}

	return "", "", fmt.Errorf("timeout waiting for pairing file")
}
