package downloader

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// FirmwareInfo represents firmware information from OTA API
type FirmwareInfo struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version"`
	Size         int64  `json:"size"`
	Checksum     string `json:"checkSum"`
	URL          string `json:"url"`
	ChangelogB64 string `json:"changeLog,omitempty"`
}

// Changelog decodes and returns the changelog
func (f *FirmwareInfo) Changelog() string {
	if f.ChangelogB64 == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(f.ChangelogB64)
	if err != nil {
		return f.ChangelogB64
	}
	return string(decoded)
}

// ModelConfig represents configuration for a robot model
type ModelConfig struct {
	ModelID         string
	Name            string
	FirmwareModules []string
}

// Client handles communication with Ecovacs OTA API
type Client struct {
	Server     string
	HTTPClient *http.Client
}

// DefaultServers contains the list of known Ecovacs servers
var DefaultServers = []string{
	"portal-ww.ecouser.net",
	"portal-us.ecouser.net",
	"portal-eu.ecouser.net",
	"portal-cn.ecouser.net",
}

// DefaultModels contains known model configurations
var DefaultModels = map[string]ModelConfig{
	"659yh8": {
		ModelID:         "659yh8",
		Name:            "DEEBOT T9 AIVI",
		FirmwareModules: []string{"fw0", "AIConfig"},
	},
	"snxbvc": {
		ModelID:         "snxbvc",
		Name:            "DEEBOT N8 PRO",
		FirmwareModules: []string{"fw0", "AIConfig"},
	},
	"lhbd50": {
		ModelID:         "lhbd50",
		Name:            "DEEBOT T9+ (PX30, fw 1.x)",
		FirmwareModules: []string{"fw0"},
	},
	"dj8zpr": {
		ModelID:         "dj8zpr",
		Name:            "DEEBOT T9 Power / T9+ (RV1126, fw 2.x)",
		FirmwareModules: []string{"fw0"},
	},
}

const userAgent = "Dalvik/2.1.0 (Linux; U; Android 5.1.1; A5010 Build/LMY48Z)"

// NewClient creates a new OTA client
func NewClient(server string) *Client {
	if server == "" {
		server = DefaultServers[0]
	}

	return &Client{
		Server: server,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// buildOTAURL constructs the OTA API URL
func (c *Client) buildOTAURL(model, version, module string) string {
	return fmt.Sprintf("https://%s:443/api/ota/products/wukong/class/%s/firmware/latest.json?ver=%s&module=%s",
		c.Server, model, version, module)
}

// CheckFirmware checks for firmware update
func (c *Client) CheckFirmware(model, version, module string) (*FirmwareInfo, error) {
	url := c.buildOTAURL(model, version, module)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if string(body) == "Not Found" {
		return nil, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract module-specific firmware info
	moduleData, ok := data[module].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	fwInfo := &FirmwareInfo{}

	if v, ok := data["name"].(string); ok {
		fwInfo.Name = v
	}
	if v, ok := moduleData["version"].(string); ok {
		fwInfo.Version = v
	}
	if v, ok := moduleData["size"].(float64); ok {
		fwInfo.Size = int64(v)
	}
	if v, ok := moduleData["checkSum"].(string); ok {
		fwInfo.Checksum = v
	}
	if v, ok := moduleData["url"].(string); ok {
		fwInfo.URL = v
	}
	if v, ok := moduleData["changeLog"].(string); ok {
		fwInfo.ChangelogB64 = v
	}

	if fwInfo.Version == "" || fwInfo.URL == "" {
		return nil, nil
	}

	return fwInfo, nil
}

// DownloadProgress represents download progress information
type DownloadProgress struct {
	BytesDownloaded int64
	TotalBytes      int64
	Speed           float64 // bytes per second
}

// ProgressCallback is called during download with progress information
type ProgressCallback func(progress DownloadProgress)

// Downloader handles firmware downloads
type Downloader struct {
	OutputDir string
}

// NewDownloader creates a new firmware downloader
func NewDownloader(outputDir string) *Downloader {
	return &Downloader{
		OutputDir: outputDir,
	}
}

// GetFilename generates a filename for firmware
func (d *Downloader) GetFilename(model, module string, firmware *FirmwareInfo) string {
	checksumShort := firmware.Checksum
	if len(checksumShort) > 8 {
		checksumShort = checksumShort[:8]
	}
	return fmt.Sprintf("%s_%s_v%s_%s.bin", model, module, firmware.Version, checksumShort)
}

// DownloadFirmware downloads a firmware file with progress tracking
func (d *Downloader) DownloadFirmware(model, module string, firmware *FirmwareInfo, progressCallback ProgressCallback) (string, error) {
	if err := os.MkdirAll(d.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	filename := d.GetFilename(model, module, firmware)
	filepath := filepath.Join(d.OutputDir, filename)

	// Check if file already exists and is valid
	if _, err := os.Stat(filepath); err == nil {
		if valid, _ := d.VerifyChecksum(filepath, firmware.Checksum); valid {
			return filepath, nil
		}
	}

	// Download file
	resp, err := http.Get(firmware.URL)
	if err != nil {
		return "", fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	file, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Download with progress tracking
	var downloaded int64
	startTime := time.Now()
	buffer := make([]byte, 32*1024) // 32KB buffer

	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := file.Write(buffer[:n]); writeErr != nil {
				return "", fmt.Errorf("failed to write file: %w", writeErr)
			}
			downloaded += int64(n)

			if progressCallback != nil {
				elapsed := time.Since(startTime).Seconds()
				speed := 0.0
				if elapsed > 0 {
					speed = float64(downloaded) / elapsed
				}
				progressCallback(DownloadProgress{
					BytesDownloaded: downloaded,
					TotalBytes:      firmware.Size,
					Speed:           speed,
				})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read response: %w", err)
		}
	}

	// Verify checksum
	if valid, err := d.VerifyChecksum(filepath, firmware.Checksum); err != nil {
		os.Remove(filepath)
		return "", fmt.Errorf("checksum verification error: %w", err)
	} else if !valid {
		os.Remove(filepath)
		return "", fmt.Errorf("checksum verification failed")
	}

	return filepath, nil
}

// VerifyChecksum verifies file checksum (tries both MD5 and SHA256)
func (d *Downloader) VerifyChecksum(filepath, expectedChecksum string) (bool, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()

	if _, err := io.Copy(io.MultiWriter(md5Hash, sha256Hash), file); err != nil {
		return false, err
	}

	md5Result := hex.EncodeToString(md5Hash.Sum(nil))
	sha256Result := hex.EncodeToString(sha256Hash.Sum(nil))

	expectedLower := expectedChecksum
	if len(expectedChecksum) > 0 {
		expectedLower = expectedChecksum
	}

	return md5Result == expectedLower || sha256Result == expectedLower, nil
}

// GenerateVersionPatterns generates common version patterns for scanning
func GenerateVersionPatterns(baseVersion string, maxVersions int) []string {
	var versions []string

	if baseVersion != "" {
		versions = append(versions, baseVersion)
	}

	// Known working versions
	knownVersions := []string{
		"1.17.0", "1.22.0", "1.0.0", "1.55.0", "1.2.9", "1.5.0",
		"1.4.8", "1.4.7", "1.4.6", "1.4.5", "1.4.4", "1.4.3", "1.4.2", "1.4.1", "1.4.0",
	}

	for _, v := range knownVersions {
		if len(versions) >= maxVersions {
			break
		}
		found := false
		for _, existing := range versions {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			versions = append(versions, v)
		}
	}

	// Generate patterns
	for major := 1; major <= 2 && len(versions) < maxVersions; major++ {
		for minor := 0; minor <= 10 && len(versions) < maxVersions; minor++ {
			for patch := 0; patch <= 20 && len(versions) < maxVersions; patch++ {
				v := fmt.Sprintf("%d.%d.%d", major, minor, patch)
				found := false
				for _, existing := range versions {
					if existing == v {
						found = true
						break
					}
				}
				if !found {
					versions = append(versions, v)
				}
			}
		}
	}

	if len(versions) > maxVersions {
		versions = versions[:maxVersions]
	}

	return versions
}