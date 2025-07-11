// Package main provides functionality to parse installed packages from VHD build output files.
// It supports both Ubuntu/Debian (APT) and Azure Linux (RPM) package formats.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// OSDistro represents the operating system distribution.
type OSDistro int

const (
	// DistroUnknown indicates the OS distribution could not be determined.
	DistroUnknown OSDistro = iota
	// DistroUbuntu indicates Ubuntu/Debian distribution.
	DistroUbuntu
	// DistroAzureLinux indicates Microsoft Azure Linux distribution.
	DistroAzureLinux
	// DistroMariner indicates CBL-Mariner distribution.
	DistroMariner
)

// String returns a string representation of the OSDistro.
func (d OSDistro) String() string {
	switch d {
	case DistroUbuntu:
		return "Ubuntu/Debian"
	case DistroAzureLinux:
		return "Azure Linux"
	case DistroMariner:
		return "CBL-Mariner"
	default:
		return "Unknown"
	}
}


// OSPackage represents an installed software package with its name and version.
type OSPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ContainerImage represents a pre-pulled container image as a raw string.
type ContainerImage struct {
	Name string `json:"name"`
}

// OSRelease represents operating system release information.
type OSRelease struct {
	Name        string   `json:"name"`         // NAME field
	VersionID   string   `json:"version_id"`   // VERSION_ID field
	Version     string   `json:"version"`      // VERSION field
	PrettyName  string   `json:"pretty_name"`  // PRETTY_NAME field
	ID          string   `json:"id"`           // ID field
	Distro      OSDistro `json:"distro"`       // Detected OS distribution
}

// String returns a string representation of the OSPackage.
func (p OSPackage) String() string {
	return fmt.Sprintf("%s-%s", p.Name, p.Version)
}

// String returns a string representation of the ContainerImage.
func (c ContainerImage) String() string {
	return c.Name
}

// String returns a string representation of the OSRelease.
func (r OSRelease) String() string {
	return fmt.Sprintf("%s %s (%s)", r.PrettyName, r.Version, r.Distro)
}

// Parser handles package parsing with compiled regex patterns for performance.
type Parser struct {
	ubuntuRegex    *regexp.Regexp
	rpmRegex       *regexp.Regexp
	nameVersionRpm *regexp.Regexp
}

// NewParser creates a new Parser with pre-compiled regex patterns.
func NewParser() (*Parser, error) {
	// Ubuntu/Debian format: package/source,now version arch [status]
	ubuntuRegex, err := regexp.Compile(`^([^/]+)/.*,now\s+(\S+)\s+\S+\s+\[.*\]`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Ubuntu regex: %w", err)
	}

	// RPM format: package-version-release.dist.arch (supports both azl3 and cm2)
	rpmRegex, err := regexp.Compile(`^(.+)-([^-]+\.(azl3|cm2)\.(x86_64|noarch))$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile RPM regex: %w", err)
	}

	// Name-version separator for RPM packages
	nameVersionRpm, err := regexp.Compile(`^(.+)-([0-9].*)$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile RPM name-version regex: %w", err)
	}

	return &Parser{
		ubuntuRegex:    ubuntuRegex,
		rpmRegex:       rpmRegex,
		nameVersionRpm: nameVersionRpm,
	}, nil
}

// ErrNoPackageSection is returned when no package section is found in the content.
var ErrNoPackageSection = errors.New("no package section found")

// ParseResult contains the parsing results and metadata.
type ParseResult struct {
	Packages        []OSPackage      `json:"packages"`
	ContainerImages []ContainerImage `json:"container_images,omitempty"`
	OSRelease       *OSRelease       `json:"os_release,omitempty"`
}

// Parse parses VHD build output from an io.Reader.
// It returns a ParseResult containing packages, OS release info, and parsing metadata.
func (p *Parser) Parse(reader io.Reader) (*ParseResult, error) {
	if reader == nil {
		return nil, errors.New("reader cannot be nil")
	}

	result := &ParseResult{
		Packages:        make([]OSPackage, 0, 100), // Pre-allocate with reasonable capacity
		ContainerImages: make([]ContainerImage, 0, 50), // Pre-allocate for container images
	}

	scanner := bufio.NewScanner(reader)
	// Increase buffer size for large lines
	const maxCapacity = 1024 * 1024 // 1MB
	buf := make([]byte, 0, 64*1024) // 64KB initial
	scanner.Buffer(buf, maxCapacity)

	inPackageSection := false
	inOSReleaseSection := false
	inContainerImagesSection := false
	osReleaseData := make(map[string]string)
	ubuntuPackageCount := 0
	rpmPackageCount := 0

	for scanner.Scan() {
		line := scanner.Text() // Don't trim space here to preserve "  - " prefix
		trimmedLine := strings.TrimSpace(line)

		// Check for section markers using trimmed line
		switch trimmedLine {
		case "=== Installed Packages Begin":
			inPackageSection = true
			inOSReleaseSection = false
			inContainerImagesSection = false
			continue
		case "=== Installed Packages End":
			inPackageSection = false
			continue
		case "=== os-release Begin":
			inOSReleaseSection = true
			inPackageSection = false
			inContainerImagesSection = false
			continue
		case "=== os-release End":
			inOSReleaseSection = false
			continue
		case "containerd images pre-pulled:":
			inContainerImagesSection = true
			inPackageSection = false
			inOSReleaseSection = false
			continue
		case "", "Listing...":
			if inPackageSection || inOSReleaseSection || inContainerImagesSection {
				continue
			}
		}

		if inPackageSection {
			pkg := p.parsePackageLine(trimmedLine)
			if pkg != nil {
				result.Packages = append(result.Packages, *pkg)
				
				// Count package types for format detection
				if p.isUbuntuPackageFormat(trimmedLine) {
					ubuntuPackageCount++
				} else if p.isRPMPackageFormat(trimmedLine) {
					rpmPackageCount++
				}
			}
		} else if inOSReleaseSection {
			p.parseOSReleaseLine(trimmedLine, osReleaseData)
		} else if inContainerImagesSection {
			// Check if this line is a container image entry (starts with "  - ")
			if strings.HasPrefix(line, "  - ") {
				image := p.parseContainerImageLine(line)
				if image != nil {
					result.ContainerImages = append(result.ContainerImages, *image)
				}
			} else if trimmedLine != "" {
				// Non-empty line that doesn't start with "  - " means end of section
				inContainerImagesSection = false
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading content: %w", err)
	}

	// Determine distro based on package counts and OS release ID
	var detectedDistro OSDistro = DistroUnknown
	
	// First try to detect from OS release ID if available
	if len(osReleaseData) > 0 {
		detectedDistro = p.detectDistroFromID(osReleaseData["ID"])
	}
	
	// If OS release didn't provide clear answer, use package counts
	if detectedDistro == DistroUnknown {
		if rpmPackageCount > ubuntuPackageCount {
			detectedDistro = DistroAzureLinux
		} else if ubuntuPackageCount > rpmPackageCount {
			detectedDistro = DistroUbuntu
		}
		// If counts are equal, leave as Unknown - will be resolved by context
	}
	
	// Build OS release info if we found any
	if len(osReleaseData) > 0 {
		
		result.OSRelease = &OSRelease{
			Name:       osReleaseData["NAME"],
			VersionID:  osReleaseData["VERSION_ID"],
			Version:    osReleaseData["VERSION"],
			PrettyName: osReleaseData["PRETTY_NAME"],
			ID:         osReleaseData["ID"],
			Distro:     detectedDistro,
		}
	}

	if len(result.Packages) == 0 && len(result.ContainerImages) == 0 && result.OSRelease == nil {
		return result, ErrNoPackageSection
	}

	return result, nil
}


// parsePackageLine parses a single package line and returns a OSPackage or nil.
func (p *Parser) parsePackageLine(line string) *OSPackage {
	if line == "" {
		return nil
	}

	// Try Ubuntu format first (more specific pattern)
	if matches := p.ubuntuRegex.FindStringSubmatch(line); len(matches) >= 3 {
		return &OSPackage{
			Name:    matches[1],
			Version: matches[2],
		}
	}

	// Try RPM format
	if matches := p.rpmRegex.FindStringSubmatch(line); len(matches) >= 3 {
		namePart := matches[1]
		versionPart := matches[2]

		// Extract the release version including .azl3/.cm2 but excluding architecture
		// versionPart format: "3.azl3.x86_64" or "20.cm2.x86_64" -> we want "3.azl3" or "20.cm2"
		releaseVersion := versionPart
		if idx := strings.LastIndex(versionPart, "."); idx != -1 {
			// Check if the last part is architecture (x86_64 or noarch)
			arch := versionPart[idx+1:]
			if arch == "x86_64" || arch == "noarch" {
				releaseVersion = versionPart[:idx]
			}
		}

		// Split name and version for RPM packages
		if nameVersionMatches := p.nameVersionRpm.FindStringSubmatch(namePart); len(nameVersionMatches) >= 3 {
			return &OSPackage{
				Name:    nameVersionMatches[1],
				Version: nameVersionMatches[2] + "-" + releaseVersion,
			}
		}

		// Fallback for RPM packages where name-version split fails
		return &OSPackage{
			Name:    namePart,
			Version: releaseVersion,
		}
	}

	return nil
}

// parseOSReleaseLine parses a single OS release line and adds it to the data map.
func (p *Parser) parseOSReleaseLine(line string, data map[string]string) {
	if line == "" {
		return
	}
	
	// OS release format: KEY="value" or KEY=value
	if idx := strings.Index(line, "="); idx > 0 {
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		
		// Remove surrounding quotes if present
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		
		// Only store the fields we're interested in
		switch key {
		case "NAME", "VERSION_ID", "VERSION", "PRETTY_NAME", "ID":
			data[key] = value
		}
	}
}

// parseContainerImageLine parses a single container image line and returns a ContainerImage or nil.
func (p *Parser) parseContainerImageLine(line string) *ContainerImage {
	if line == "" {
		return nil
	}
	
	// Check if line starts with "  - " prefix
	if !strings.HasPrefix(line, "  - ") {
		return nil
	}
	
	// Remove the "  - " prefix and keep the image name as-is
	imageName := strings.TrimSpace(strings.TrimPrefix(line, "  - "))
	if imageName == "" {
		return nil
	}
	
	return &ContainerImage{
		Name: imageName,
	}
}

// isUbuntuPackageFormat checks if a line matches Ubuntu/Debian package format.
func (p *Parser) isUbuntuPackageFormat(line string) bool {
	return p.ubuntuRegex.MatchString(line)
}

// isRPMPackageFormat checks if a line matches RPM package format.
func (p *Parser) isRPMPackageFormat(line string) bool {
	return p.rpmRegex.MatchString(line)
}

// detectDistroFromID detects the OS distribution from the os-release ID field.
func (p *Parser) detectDistroFromID(id string) OSDistro {
	switch id {
	case "ubuntu", "debian":
		return DistroUbuntu
	case "azurelinux":
		return DistroAzureLinux
	case "mariner":
		return DistroMariner
	default:
		return DistroUnknown
	}
}


// ParseFromFile reads and parses VHD build output from a file.
func (p *Parser) ParseFromFile(filename string) (*ParseResult, error) {
	if filename == "" {
		return nil, errors.New("filename cannot be empty")
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	return p.Parse(file)
}
