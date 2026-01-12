package main

import (
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
