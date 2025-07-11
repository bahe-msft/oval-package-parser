package main

import (
	"errors"
	"strings"
	"testing"
)

func TestNewParser(t *testing.T) {
	parser, err := NewParser()
	if err != nil {
		t.Fatalf("NewParser() failed: %v", err)
	}
	if parser == nil {
		t.Fatal("NewParser() returned nil parser")
	}
	if parser.ubuntuRegex == nil || parser.rpmRegex == nil || parser.nameVersionRpm == nil {
		t.Fatal("NewParser() did not initialize all regex patterns")
	}
}


func TestOSPackage_String(t *testing.T) {
	pkg := OSPackage{
		Name:    "test-package",
		Version: "1.0.0",
	}
	expected := "test-package-1.0.0"
	if got := pkg.String(); got != expected {
		t.Errorf("OSPackage.String() = %q, want %q", got, expected)
	}
}

func TestOSRelease_String(t *testing.T) {
	release := OSRelease{
		Name:       "Microsoft Azure Linux",
		VersionID:  "3.0",
		Version:    "3.0.20250602",
		PrettyName: "Microsoft Azure Linux 3.0",
		ID:         "azurelinux",
		Distro:     DistroAzureLinux,
	}
	expected := "Microsoft Azure Linux 3.0 3.0.20250602 (Azure Linux)"
	if got := release.String(); got != expected {
		t.Errorf("OSRelease.String() = %q, want %q", got, expected)
	}
}

func TestOSDistro_String(t *testing.T) {
	tests := []struct {
		distro   OSDistro
		expected string
	}{
		{DistroUnknown, "Unknown"},
		{DistroUbuntu, "Ubuntu/Debian"},
		{DistroAzureLinux, "Azure Linux"},
		{DistroMariner, "CBL-Mariner"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.distro.String(); got != tt.expected {
				t.Errorf("OSDistro.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerImage_String(t *testing.T) {
	image := ContainerImage{
		Name: "mcr.microsoft.com/oss/kubernetes/pause:3.6",
	}
	expected := "mcr.microsoft.com/oss/kubernetes/pause:3.6"
	if got := image.String(); got != expected {
		t.Errorf("ContainerImage.String() = %q, want %q", got, expected)
	}
}

func TestParser_parseContainerImageLine(t *testing.T) {
	parser, err := NewParser()
	if err != nil {
		t.Fatalf("NewParser() failed: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected *ContainerImage
	}{
		{
			name:  "Microsoft container image with tag",
			input: "  - mcr.microsoft.com/oss/kubernetes/pause:3.6",
			expected: &ContainerImage{
				Name: "mcr.microsoft.com/oss/kubernetes/pause:3.6",
			},
		},
		{
			name:  "Azure CNI container image",
			input: "  - mcr.microsoft.com/containernetworking/azure-cni:v1.4.59",
			expected: &ContainerImage{
				Name: "mcr.microsoft.com/containernetworking/azure-cni:v1.4.59",
			},
		},
		{
			name:  "Complex nested repository path",
			input: "  - mcr.microsoft.com/oss/v2/kubernetes/autoscaler/addon-resizer:v1.8.23-2",
			expected: &ContainerImage{
				Name: "mcr.microsoft.com/oss/v2/kubernetes/autoscaler/addon-resizer:v1.8.23-2",
			},
		},
		{
			name:  "Image without tag",
			input: "  - mcr.microsoft.com/oss/kubernetes/pause",
			expected: &ContainerImage{
				Name: "mcr.microsoft.com/oss/kubernetes/pause",
			},
		},
		{
			name:     "Empty line",
			input:    "",
			expected: nil,
		},
		{
			name:     "Line with only prefix",
			input:    "  - ",
			expected: nil,
		},
		{
			name:     "Line without prefix",
			input:    "mcr.microsoft.com/oss/kubernetes/pause:3.6",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.parseContainerImageLine(tt.input)
			if !containerImageEqual(result, tt.expected) {
				t.Errorf("parseContainerImageLine(%q) = %+v, want %+v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParser_parsePackageLine(t *testing.T) {
	parser, err := NewParser()
	if err != nil {
		t.Fatalf("NewParser() failed: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected *OSPackage
	}{
		{
			name:  "Ubuntu package format",
			input: "adduser/noble,now 3.137ubuntu1 all [installed,automatic]",
			expected: &OSPackage{
				Name:    "adduser",
				Version: "3.137ubuntu1",
			},
		},
		{
			name:  "Ubuntu package with complex version",
			input: "apparmor/noble-updates,now 4.0.1really4.0.1-0ubuntu0.24.04.4 amd64 [installed,automatic]",
			expected: &OSPackage{
				Name:    "apparmor",
				Version: "4.0.1really4.0.1-0ubuntu0.24.04.4",
			},
		},
		{
			name:  "Ubuntu package with multiple sources",
			input: "bind9-dnsutils/noble-updates,noble-security,now 1:9.18.30-0ubuntu0.24.04.2 amd64 [installed]",
			expected: &OSPackage{
				Name:    "bind9-dnsutils",
				Version: "1:9.18.30-0ubuntu0.24.04.2",
			},
		},
		{
			name:  "RPM package format simple",
			input: "filesystem-1.1-21.azl3.x86_64",
			expected: &OSPackage{
				Name:    "filesystem",
				Version: "1.1-21.azl3",
			},
		},
		{
			name:  "RPM package format complex",
			input: "python3-cryptography-42.0.5-3.azl3.x86_64",
			expected: &OSPackage{
				Name:    "python3-cryptography",
				Version: "42.0.5-3.azl3",
			},
		},
		{
			name:  "RPM package noarch",
			input: "cloud-init-azure-kvp-24.3.1-1.azl3.noarch",
			expected: &OSPackage{
				Name:    "cloud-init-azure-kvp",
				Version: "24.3.1-1.azl3",
			},
		},
		{
			name:  "RPM package with multiple version segments",
			input: "kernel-devel-5.15.167.4-1.azl3.x86_64",
			expected: &OSPackage{
				Name:    "kernel-devel",
				Version: "5.15.167.4-1.azl3",
			},
		},
		{
			name:  "RPM package with epoch in version",
			input: "glibc-2.38-10.azl3.x86_64",
			expected: &OSPackage{
				Name:    "glibc",
				Version: "2.38-10.azl3",
			},
		},
		{
			name:  "Mariner package format simple",
			input: "filesystem-1.1-20.cm2.x86_64",
			expected: &OSPackage{
				Name:    "filesystem",
				Version: "1.1-20.cm2",
			},
		},
		{
			name:  "Mariner package format complex",
			input: "python3-cryptography-42.0.5-3.cm2.x86_64",
			expected: &OSPackage{
				Name:    "python3-cryptography",
				Version: "42.0.5-3.cm2",
			},
		},
		{
			name:  "Mariner package noarch",
			input: "cloud-init-azure-kvp-24.3.1-1.cm2.noarch",
			expected: &OSPackage{
				Name:    "cloud-init-azure-kvp",
				Version: "24.3.1-1.cm2",
			},
		},
		{
			name:     "Empty line",
			input:    "",
			expected: nil,
		},
		{
			name:     "Whitespace only",
			input:    "   ",
			expected: nil,
		},
		{
			name:     "Invalid format",
			input:    "invalid package line",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.parsePackageLine(tt.input)
			if !packageEqual(result, tt.expected) {
				t.Errorf("parsePackageLine(%q) = %+v, want %+v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParser_parseOSReleaseLine(t *testing.T) {
	parser, err := NewParser()
	if err != nil {
		t.Fatalf("NewParser() failed: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "NAME with quotes",
			input:    `NAME="Microsoft Azure Linux"`,
			expected: map[string]string{"NAME": "Microsoft Azure Linux"},
		},
		{
			name:     "VERSION_ID without quotes",
			input:    "VERSION_ID=3.0",
			expected: map[string]string{"VERSION_ID": "3.0"},
		},
		{
			name:     "VERSION with quotes",
			input:    `VERSION="3.0.20250602"`,
			expected: map[string]string{"VERSION": "3.0.20250602"},
		},
		{
			name:     "PRETTY_NAME with quotes",
			input:    `PRETTY_NAME="Microsoft Azure Linux 3.0"`,
			expected: map[string]string{"PRETTY_NAME": "Microsoft Azure Linux 3.0"},
		},
		{
			name:     "ID without quotes",
			input:    "ID=azurelinux",
			expected: map[string]string{"ID": "azurelinux"},
		},
		{
			name:     "Ignored field",
			input:    `HOME_URL="https://aka.ms/azurelinux"`,
			expected: map[string]string{},
		},
		{
			name:     "Empty line",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:     "Invalid format",
			input:    "invalid line",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make(map[string]string)
			parser.parseOSReleaseLine(tt.input, data)
			
			if len(data) != len(tt.expected) {
				t.Errorf("parseOSReleaseLine() got %d items, want %d", len(data), len(tt.expected))
			}
			
			for key, expectedValue := range tt.expected {
				if actualValue, exists := data[key]; !exists {
					t.Errorf("parseOSReleaseLine() missing key %q", key)
				} else if actualValue != expectedValue {
					t.Errorf("parseOSReleaseLine() key %q = %q, want %q", key, actualValue, expectedValue)
				}
			}
		})
	}
}

func TestParser_Parse(t *testing.T) {
	parser, err := NewParser()
	if err != nil {
		t.Fatalf("NewParser() failed: %v", err)
	}

	tests := []struct {
		name                     string
		content                  string
		expectedCount            int
		expectedContainerImages  int
		expectedError            error
		expectedOSRelease        *OSRelease
	}{
		{
			name: "Full VHD build output with OS release and container images",
			content: `Starting build
=== Installed Packages Begin
adduser/noble,now 3.137ubuntu1 all [installed,automatic]
filesystem-1.1-21.azl3.x86_64
=== Installed Packages End
containerd images pre-pulled:
  - mcr.microsoft.com/oss/kubernetes/pause:3.6
  - mcr.microsoft.com/containernetworking/azure-cni:v1.4.59
  - mcr.microsoft.com/oss/v2/kubernetes/coredns:v1.11.3-8
Successfully copied coredns binary
=== os-release Begin
NAME="Microsoft Azure Linux"
VERSION="3.0.20250602"
ID=azurelinux
VERSION_ID="3.0"
PRETTY_NAME="Microsoft Azure Linux 3.0"
HOME_URL="https://aka.ms/azurelinux"
=== os-release End`,
			expectedCount:           2,
			expectedContainerImages: 3,
			expectedOSRelease: &OSRelease{
				Name:       "Microsoft Azure Linux",
				VersionID:  "3.0",
				Version:    "3.0.20250602",
				PrettyName: "Microsoft Azure Linux 3.0",
				ID:         "azurelinux",
				Distro:     DistroAzureLinux,
			},
		},
		{
			name: "Only packages, no OS release",
			content: `=== Installed Packages Begin
adduser/noble,now 3.137ubuntu1 all [installed,automatic]
=== Installed Packages End`,
			expectedCount:           1,
			expectedContainerImages: 0,
			expectedOSRelease:       nil,
		},
		{
			name: "Only container images, no packages",
			content: `containerd images pre-pulled:
  - mcr.microsoft.com/oss/kubernetes/pause:3.6
  - mcr.microsoft.com/containernetworking/azure-cni:v1.4.59
Successfully copied coredns binary`,
			expectedCount:           0,
			expectedContainerImages: 2,
			expectedOSRelease:       nil,
		},
		{
			name: "Only OS release, no packages",
			content: `=== os-release Begin
NAME="Ubuntu"
VERSION="24.04"
ID=ubuntu
VERSION_ID="24.04"
PRETTY_NAME="Ubuntu 24.04 LTS"
=== os-release End`,
			expectedCount:           0,
			expectedContainerImages: 0,
			expectedOSRelease: &OSRelease{
				Name:       "Ubuntu",
				VersionID:  "24.04",
				Version:    "24.04",
				PrettyName: "Ubuntu 24.04 LTS",
				ID:         "ubuntu",
				Distro:     DistroUbuntu,
			},
		},
		{
			name: "No sections",
			content: `Starting build
Components downloaded:
Disk usage:`,
			expectedCount:           0,
			expectedContainerImages: 0,
			expectedError:           ErrNoPackageSection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parser.Parse(strings.NewReader(tt.content))
			
			if tt.expectedError != nil {
				if !errors.Is(err, tt.expectedError) {
					t.Errorf("Parse() error = %v, want %v", err, tt.expectedError)
				}
				return
			}
			
			if err != nil {
				t.Errorf("Parse() unexpected error = %v", err)
				return
			}
			
			if len(result.Packages) != tt.expectedCount {
				t.Errorf("Parse() count = %d, want %d", len(result.Packages), tt.expectedCount)
			}
			
			if len(result.ContainerImages) != tt.expectedContainerImages {
				t.Errorf("Parse() container images count = %d, want %d", len(result.ContainerImages), tt.expectedContainerImages)
			}
			
			if tt.expectedOSRelease == nil {
				if result.OSRelease != nil {
					t.Errorf("Parse() got OS release %+v, want nil", result.OSRelease)
				}
			} else {
				if result.OSRelease == nil {
					t.Errorf("Parse() got nil OS release, want %+v", tt.expectedOSRelease)
				} else {
					if result.OSRelease.Name != tt.expectedOSRelease.Name ||
						result.OSRelease.Version != tt.expectedOSRelease.Version ||
						result.OSRelease.VersionID != tt.expectedOSRelease.VersionID ||
						result.OSRelease.PrettyName != tt.expectedOSRelease.PrettyName ||
						result.OSRelease.ID != tt.expectedOSRelease.ID ||
						result.OSRelease.Distro != tt.expectedOSRelease.Distro {
						t.Errorf("Parse() OS release = %+v, want %+v", result.OSRelease, tt.expectedOSRelease)
					}
				}
			}
		})
	}
}




func TestParser_ParseFromFile_ErrorCases(t *testing.T) {
	parser, err := NewParser()
	if err != nil {
		t.Fatalf("NewParser() failed: %v", err)
	}

	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "Empty filename",
			filename: "",
			wantErr:  true,
		},
		{
			name:     "Non-existent file",
			filename: "/non/existent/file.txt",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.ParseFromFile(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFromFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// packageEqual compares two OSPackage pointers for equality
func packageEqual(a, b *OSPackage) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Name == b.Name && a.Version == b.Version
}

// containerImageEqual compares two ContainerImage pointers for equality
func containerImageEqual(a, b *ContainerImage) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Name == b.Name
}

// Benchmark tests for performance comparison
func BenchmarkParser_parsePackageLine_Ubuntu(b *testing.B) {
	parser, _ := NewParser()
	line := "adduser/noble,now 3.137ubuntu1 all [installed,automatic]"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.parsePackageLine(line)
	}
}

func BenchmarkParser_parsePackageLine_RPM(b *testing.B) {
	parser, _ := NewParser()
	line := "python3-cryptography-42.0.5-3.azl3.x86_64"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.parsePackageLine(line)
	}
}

func BenchmarkParser_Parse(b *testing.B) {
	parser, _ := NewParser()
	content := `=== Installed Packages Begin
adduser/noble,now 3.137ubuntu1 all [installed,automatic]
apparmor/noble-updates,now 4.0.1really4.0.1-0ubuntu0.24.04.4 amd64 [installed,automatic]
filesystem-1.1-21.azl3.x86_64
python3-cryptography-42.0.5-3.azl3.x86_64
=== Installed Packages End
=== os-release Begin
NAME="Microsoft Azure Linux"
VERSION="3.0.20250602"
ID=azurelinux
VERSION_ID="3.0"
PRETTY_NAME="Microsoft Azure Linux 3.0"
=== os-release End`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.Parse(strings.NewReader(content))
	}
}
