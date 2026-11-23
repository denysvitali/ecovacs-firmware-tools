package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Section represents a firmware section with the new format
type Section struct {
	Offset         int
	Unkn1          uint8
	Type           uint8 // type_maybe field
	Unkn2          uint16
	Size           int
	DataOffset     int
	ChecksumOffset int
	Header         []byte
	Checksum       string // 64-byte SHA256 checksum as hex string
}

// ManifestSection represents a section in the firmware manifest
type ManifestSection struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Size     int    `json:"size"`
	Skip     string `json:"skip"`
	FlashCmd string `json:"flash_cmd"`
}

// Manifest represents the firmware manifest structure
type Manifest struct {
	FwVer       string            `json:"fw_ver"`
	HwVer       string            `json:"hw_ver"`
	Product     string            `json:"product"`
	ReleaseDate string            `json:"release_date"`
	Sections    []ManifestSection `json:"sections"`
}

// Decryptor handles firmware decryption
type Decryptor struct {
	FirmwarePath string
	DeviceID     string
	Platform     string
	Param        string
	Version      int
	FirmwareData []byte
}

// NewDecryptor creates a new decryptor instance
func NewDecryptor(firmwarePath, deviceID, platform, param string, version int) (*Decryptor, error) {
	d := &Decryptor{
		FirmwarePath: firmwarePath,
		DeviceID:     deviceID,
		Platform:     platform,
		Param:        param,
		Version:      version,
	}

	if err := d.loadFirmware(); err != nil {
		return nil, err
	}

	return d, nil
}

// loadFirmware loads firmware file into memory
func (d *Decryptor) loadFirmware() error {
	data, err := os.ReadFile(d.FirmwarePath)
	if err != nil {
		return fmt.Errorf("failed to read firmware file: %w", err)
	}
	d.FirmwareData = data
	return nil
}

// deriveEcovacsKey derives the encryption key and IV for a section
func (d *Decryptor) deriveEcovacsKey(sectionType int, sectionSize int) ([]byte, []byte, error) {
	typeDigit := sectionType
	sizeHex := fmt.Sprintf("%x", sectionSize)

	// The platform token is the second %s of the key format string. It was
	// hardcoded to "px30", so non-PX30 devices (e.g. the RV1126 Deebot T9+
	// with product "rv1126_zj2010") could not be decrypted even though
	// --platform was already plumbed through to this type.
	platform := d.Platform
	if platform == "" {
		platform = "px30"
	}

	snprintfResult := fmt.Sprintf("ZWNvX2Z3X3RhcmdldCAECO-PT1jdSAt%sbyBtYW4%dy5iaW4%s825xxjeff-hk@126.com",
		platform, typeDigit, sizeHex)

	originalLen := len(snprintfResult)
	encoded := base64.StdEncoding.EncodeToString([]byte(snprintfResult))

	if len(encoded) < 4 {
		return nil, nil, fmt.Errorf("base64 encoding too short")
	}
	encodedSkipped := encoded[4:]

	if len(encodedSkipped) > originalLen {
		encodedSkipped = encodedSkipped[:originalLen]
	}

	hash := sha256.Sum256([]byte(encodedSkipped))
	hashHex := hex.EncodeToString(hash[:])

	if len(hashHex) < 51 {
		return nil, nil, fmt.Errorf("hash too short for key/IV extraction")
	}

	ivAscii := hashHex[0:16]
	keyAscii := hashHex[35:51]

	iv := []byte(ivAscii)
	key := []byte(keyAscii)

	return key, iv, nil
}

// parseElementHeader parses 8-byte element header at given offset
func (d *Decryptor) parseElementHeader(offset int) (*Section, error) {
	if offset+8 > len(d.FirmwareData) {
		return nil, fmt.Errorf("offset beyond firmware size")
	}

	header := d.FirmwareData[offset : offset+8]
	unkn1 := header[0]
	typeMaybe := header[1]
	unkn2 := binary.LittleEndian.Uint16(header[2:4])
	size := binary.LittleEndian.Uint32(header[4:8])

	dataOffset := offset + 8
	checksumOffset := dataOffset + int(size)

	if checksumOffset+64 > len(d.FirmwareData) {
		return nil, fmt.Errorf("checksum extends beyond firmware size")
	}

	checksumBytes := d.FirmwareData[checksumOffset : checksumOffset+64]
	checksum := string(checksumBytes)

	return &Section{
		Offset:         offset,
		Unkn1:          unkn1,
		Type:           typeMaybe,
		Unkn2:          unkn2,
		Size:           int(size),
		DataOffset:     dataOffset,
		ChecksumOffset: checksumOffset,
		Header:         header,
		Checksum:       checksum,
	}, nil
}

// FindSections finds all valid firmware sections
func (d *Decryptor) FindSections() ([]*Section, error) {
	var sections []*Section
	offset := 0

	for offset < len(d.FirmwareData)-72 {
		section, err := d.parseElementHeader(offset)
		if err != nil {
			offset++
			continue
		}

		if section.Size <= 0 || section.Size > len(d.FirmwareData) {
			offset++
			continue
		}

		totalSectionSize := 8 + section.Size + 64
		if offset+totalSectionSize > len(d.FirmwareData) {
			offset++
			continue
		}

		if section.Unkn1 != 1 || section.Type != 1 {
			offset++
			continue
		}

		if len(section.Checksum) != 64 {
			offset++
			continue
		}

		sections = append(sections, section)
		offset += totalSectionSize

		for offset < len(d.FirmwareData) && d.FirmwareData[offset] == 0 {
			offset++
		}
	}

	return sections, nil
}

// parseManifest parses the decrypted manifest JSON
func (d *Decryptor) parseManifest(decryptedData []byte) (*Manifest, error) {
	decryptedData = d.removePKCS7Padding(decryptedData)

	var manifest Manifest
	err := json.Unmarshal(decryptedData, &manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	return &manifest, nil
}

// removePKCS7Padding removes PKCS7 padding from decrypted data
func (d *Decryptor) removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	paddingSize := int(data[len(data)-1])
	if paddingSize > len(data) || paddingSize > 16 {
		return data
	}

	for i := len(data) - paddingSize; i < len(data); i++ {
		if data[i] != byte(paddingSize) {
			return data
		}
	}

	return data[:len(data)-paddingSize]
}

// VerifyChecksum verifies the SHA256 checksum of data
func (d *Decryptor) VerifyChecksum(data []byte, expectedChecksum string) bool {
	hash := sha256.Sum256(data)
	actualChecksum := hex.EncodeToString(hash[:])
	return actualChecksum == expectedChecksum || actualChecksum == expectedChecksum[:len(actualChecksum)]
}

// DeriveKey derives the encryption key and IV for a section (exported for CLI)
func (d *Decryptor) DeriveKey(sectionType int, sectionSize int) ([]byte, []byte, error) {
	return d.deriveEcovacsKey(sectionType, sectionSize)
}

// ParseManifest parses the decrypted manifest JSON (exported for CLI)
func (d *Decryptor) ParseManifest(decryptedData []byte) (*Manifest, error) {
	return d.parseManifest(decryptedData)
}

// DecryptSection decrypts a section using AES-CBC (exported for CLI)
func (d *Decryptor) DecryptSection(sectionData, key, iv []byte) ([]byte, error) {
	return d.decryptSection(sectionData, key, iv)
}

// decryptSection decrypts a section using AES-CBC
func (d *Decryptor) decryptSection(sectionData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(sectionData)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(sectionData))
	mode.CryptBlocks(decrypted, sectionData)

	return decrypted, nil
}

// DecryptedSection represents a successfully decrypted section
type DecryptedSection struct {
	Section        *Section
	DecryptedData  []byte
	ChecksumValid  bool
	OutputFilename string
	Manifest       *Manifest // Only populated for manifest sections
}

// DecryptAll decrypts all firmware sections
func (d *Decryptor) DecryptAll(outputDir string) ([]*DecryptedSection, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	sections, err := d.FindSections()
	if err != nil {
		return nil, fmt.Errorf("failed to find firmware sections: %w", err)
	}

	// First pass: Decrypt and parse the first section as the manifest
	if len(sections) == 0 {
		return nil, fmt.Errorf("no sections found")
	}

	var manifest *Manifest
	firstSection := sections[0]
	sectionType := int(firstSection.Unkn2 >> 12)
	encryptedData := d.FirmwareData[firstSection.DataOffset : firstSection.DataOffset+firstSection.Size]

	key, iv, err := d.deriveEcovacsKey(sectionType, firstSection.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key for manifest: %w", err)
	}

	decrypted, err := d.decryptSection(encryptedData, key, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt manifest: %w", err)
	}

	decryptedUnpadded := d.removePKCS7Padding(decrypted)
	manifest, err = d.parseManifest(decryptedUnpadded)
	if err != nil {
		return nil, fmt.Errorf("first section is not a valid manifest: %w", err)
	}

	if len(manifest.Sections) == 0 {
		return nil, fmt.Errorf("manifest contains no sections")
	}

	// Second pass: Decrypt all sections with proper names
	var results []*DecryptedSection
	manifestFound := false

	for i, section := range sections {
		sectionType := int(section.Unkn2 >> 12)
		encryptedData := d.FirmwareData[section.DataOffset : section.DataOffset+section.Size]

		key, iv, err := d.deriveEcovacsKey(sectionType, section.Size)
		if err != nil {
			continue
		}

		checksumData := d.FirmwareData[section.Offset : section.Offset+8+section.Size]
		checksumValid := d.VerifyChecksum(checksumData, section.Checksum)

		decrypted, err := d.decryptSection(encryptedData, key, iv)
		if err != nil {
			continue
		}

		decryptedUnpadded := d.removePKCS7Padding(decrypted)

		outputFile := d.getSectionFilename(section, manifest, i)
		fullPath := filepath.Join(outputDir, outputFile)

		var dataToWrite []byte
		if manifest != nil && i == 0 {
			// For the manifest, write formatted JSON
			prettyJSON, err := json.MarshalIndent(manifest, "", "  ")
			if err != nil {
				continue
			}
			dataToWrite = append(prettyJSON, '\n')
		} else {
			dataToWrite = decryptedUnpadded
		}

		if err := os.WriteFile(fullPath, dataToWrite, 0644); err != nil {
			continue
		}

		result := &DecryptedSection{
			Section:        section,
			DecryptedData:  decryptedUnpadded,
			ChecksumValid:  checksumValid,
			OutputFilename: outputFile,
		}

		// Store manifest reference for manifest section
		if manifest != nil && !manifestFound {
			result.Manifest = manifest
			manifestFound = true
		}

		results = append(results, result)
	}

	return results, nil
}

// getExtensionFromType returns the appropriate file extension for a section type
func getExtensionFromType(sectionType string) string {
	switch sectionType {
	case "sh_script":
		return ".sh"
	case "bin":
		return ".bin"
	case "fs":
		return ".img"
	case "img":
		return ".img"
	default:
		return ".bin"
	}
}

// getSectionFilename returns appropriate filename for a section
func (d *Decryptor) getSectionFilename(section *Section, manifest *Manifest, sectionIndex int) string {
	// If we have a manifest and this is the first section (index 0), it's the manifest
	if manifest != nil && sectionIndex == 0 {
		return "manifest.json"
	}

	// If we have a manifest and valid index, use the section name and type
	if manifest != nil && sectionIndex > 0 && sectionIndex <= len(manifest.Sections) {
		manifestSection := manifest.Sections[sectionIndex-1]
		ext := getExtensionFromType(manifestSection.Type)
		return manifestSection.Name + ext
	}

	// Fallback to old naming scheme
	return fmt.Sprintf("section_%d.bin", section.Unkn2)
}

