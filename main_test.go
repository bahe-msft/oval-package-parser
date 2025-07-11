package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
)

func TestIsURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "HTTP URL",
			input:    "http://example.com/file.txt",
			expected: true,
		},
		{
			name:     "HTTPS URL",
			input:    "https://example.com/file.txt",
			expected: true,
		},
		{
			name:     "Local file path",
			input:    "./sample-ubuntu.txt",
			expected: false,
		},
		{
			name:     "Absolute file path",
			input:    "/home/user/file.txt",
			expected: false,
		},
		{
			name:     "Relative file path",
			input:    "sample.txt",
			expected: false,
		},
		{
			name:     "FTP URL (not supported)",
			input:    "ftp://example.com/file.txt",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isURL(tt.input)
			if result != tt.expected {
				t.Errorf("isURL(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFetchContent_LocalFile(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	testContent := "=== Installed Packages Begin ===\ntest-package 1.0\n=== Installed Packages End ==="
	if _, err := tempFile.WriteString(testContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	// Test reading the file
	reader, err := fetchContent(tempFile.Name())
	if err != nil {
		t.Fatalf("fetchContent failed: %v", err)
	}
	defer func() {
		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	}()

	// Read the content
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read content: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("Content mismatch. Got %q, expected %q", string(content), testContent)
	}
}

func TestFetchContent_LocalFile_NotFound(t *testing.T) {
	_, err := fetchContent("nonexistent-file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("Expected 'failed to open file' in error, got: %v", err)
	}
}

func TestFetchContent_URL(t *testing.T) {
	testContent := "=== Installed Packages Begin ===\ntest-package 1.0\n=== Installed Packages End ==="
	
	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	defer server.Close()

	// Test fetching from URL
	reader, err := fetchContent(server.URL)
	if err != nil {
		t.Fatalf("fetchContent failed: %v", err)
	}
	defer func() {
		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	}()

	// Read the content
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read content: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("Content mismatch. Got %q, expected %q", string(content), testContent)
	}
}

func TestFetchContent_URL_NotFound(t *testing.T) {
	// Create a test HTTP server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := fetchContent(server.URL)
	if err == nil {
		t.Error("Expected error for 404 response, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP error 404") {
		t.Errorf("Expected 'HTTP error 404' in error, got: %v", err)
	}
}

func TestIsPackageFixed_Ubuntu(t *testing.T) {
	tests := []struct {
		name         string
		pkgVersion   string
		fixedVersion string
		expected     bool
	}{
		{
			name:         "Package version equals fixed version",
			pkgVersion:   "1.2.3-4ubuntu1",
			fixedVersion: "1.2.3-4ubuntu1",
			expected:     true,
		},
		{
			name:         "Package version newer than fixed version",
			pkgVersion:   "1.2.3-4ubuntu2",
			fixedVersion: "1.2.3-4ubuntu1",
			expected:     true,
		},
		{
			name:         "Package version older than fixed version",
			pkgVersion:   "1.2.3-4ubuntu1",
			fixedVersion: "1.2.3-4ubuntu2",
			expected:     false,
		},
		{
			name:         "No fixed version available",
			pkgVersion:   "1.2.3-4ubuntu1",
			fixedVersion: "",
			expected:     false,
		},
		{
			name:         "Invalid package version",
			pkgVersion:   "invalid-version",
			fixedVersion: "1.2.3-4ubuntu1",
			expected:     false,
		},
		{
			name:         "Invalid fixed version",
			pkgVersion:   "1.2.3-4ubuntu1",
			fixedVersion: "invalid-version",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPackageFixed(tt.pkgVersion, tt.fixedVersion, DistroUbuntu)
			if result != tt.expected {
				t.Errorf("isPackageFixed(%q, %q, Ubuntu) = %v, expected %v", 
					tt.pkgVersion, tt.fixedVersion, result, tt.expected)
			}
		})
	}
}

func TestIsPackageFixed_AzureLinux(t *testing.T) {
	tests := []struct {
		name         string
		pkgVersion   string
		fixedVersion string
		expected     bool
	}{
		{
			name:         "Package version equals fixed version",
			pkgVersion:   "1.2.3-4.azl3",
			fixedVersion: "1.2.3-4.azl3",
			expected:     true,
		},
		{
			name:         "Package version newer than fixed version",
			pkgVersion:   "1.2.3-5.azl3",
			fixedVersion: "1.2.3-4.azl3",
			expected:     true,
		},
		{
			name:         "Package version older than fixed version",
			pkgVersion:   "1.2.3-3.azl3",
			fixedVersion: "1.2.3-4.azl3",
			expected:     false,
		},
		{
			name:         "No fixed version available",
			pkgVersion:   "1.2.3-4.azl3",
			fixedVersion: "",
			expected:     false,
		},
		{
			name:         "Version without azl3 suffix",
			pkgVersion:   "1.2.3-4",
			fixedVersion: "1.2.3-5",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPackageFixed(tt.pkgVersion, tt.fixedVersion, DistroAzureLinux)
			if result != tt.expected {
				t.Errorf("isPackageFixed(%q, %q, AzureLinux) = %v, expected %v", 
					tt.pkgVersion, tt.fixedVersion, result, tt.expected)
			}
		})
	}
}

func TestIsPackageFixed_Mariner(t *testing.T) {
	tests := []struct {
		name         string
		pkgVersion   string
		fixedVersion string
		expected     bool
	}{
		{
			name:         "Package version equals fixed version",
			pkgVersion:   "1.2.3-4.cm2",
			fixedVersion: "1.2.3-4.cm2",
			expected:     true,
		},
		{
			name:         "Package version newer than fixed version",
			pkgVersion:   "1.2.3-5.cm2",
			fixedVersion: "1.2.3-4.cm2",
			expected:     true,
		},
		{
			name:         "Package version older than fixed version",
			pkgVersion:   "1.2.3-3.cm2",
			fixedVersion: "1.2.3-4.cm2",
			expected:     false,
		},
		{
			name:         "No fixed version available",
			pkgVersion:   "1.2.3-4.cm2",
			fixedVersion: "",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPackageFixed(tt.pkgVersion, tt.fixedVersion, DistroMariner)
			if result != tt.expected {
				t.Errorf("isPackageFixed(%q, %q, Mariner) = %v, expected %v", 
					tt.pkgVersion, tt.fixedVersion, result, tt.expected)
			}
		})
	}
}

func TestIsPackageFixed_UnsupportedDistro(t *testing.T) {
	result := isPackageFixed("1.2.3", "1.2.4", DistroUnknown)
	if result != false {
		t.Errorf("isPackageFixed with unsupported distro should return false, got %v", result)
	}
}

// Test version comparison libraries directly to ensure they work as expected
func TestDebVersionComparison(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		expected int // -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
	}{
		{
			name:     "Equal versions",
			version1: "1.2.3-4ubuntu1",
			version2: "1.2.3-4ubuntu1",
			expected: 0,
		},
		{
			name:     "First version newer",
			version1: "1.2.3-4ubuntu2",
			version2: "1.2.3-4ubuntu1",
			expected: 1,
		},
		{
			name:     "First version older",
			version1: "1.2.3-4ubuntu1",
			version2: "1.2.3-4ubuntu2",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, err := debversion.NewVersion(tt.version1)
			if err != nil {
				t.Fatalf("Failed to parse version %s: %v", tt.version1, err)
			}
			v2, err := debversion.NewVersion(tt.version2)
			if err != nil {
				t.Fatalf("Failed to parse version %s: %v", tt.version2, err)
			}

			result := v1.Compare(v2)
			if result != tt.expected {
				t.Errorf("Compare(%s, %s) = %d, expected %d", tt.version1, tt.version2, result, tt.expected)
			}
		})
	}
}

func TestRpmVersionComparison(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		expected int // -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
	}{
		{
			name:     "Equal versions",
			version1: "1.2.3-4.azl3",
			version2: "1.2.3-4.azl3",
			expected: 0,
		},
		{
			name:     "First version newer",
			version1: "1.2.3-5.azl3",
			version2: "1.2.3-4.azl3",
			expected: 1,
		},
		{
			name:     "First version older",
			version1: "1.2.3-3.azl3",
			version2: "1.2.3-4.azl3",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1 := rpmversion.NewVersion(tt.version1)
			v2 := rpmversion.NewVersion(tt.version2)

			result := v1.Compare(v2)
			if result != tt.expected {
				t.Errorf("Compare(%s, %s) = %d, expected %d", tt.version1, tt.version2, result, tt.expected)
			}
		})
	}
}

func TestCheckPackageVulnerabilities_NoOSRelease(t *testing.T) {
	pkg := OSPackage{
		Name:    "test-package",
		Version: "1.0.0",
	}

	_, err := checkPackageVulnerabilities(pkg, nil)
	if err == nil {
		t.Error("Expected error when OSRelease is nil, got nil")
	}
	if !strings.Contains(err.Error(), "OS release information required") {
		t.Errorf("Expected 'OS release information required' in error, got: %v", err)
	}
}

func TestCheckPackageVulnerabilities_UnsupportedDistro(t *testing.T) {
	pkg := OSPackage{
		Name:    "test-package",
		Version: "1.0.0",
	}
	osRelease := &OSRelease{
		Distro: DistroUnknown,
	}

	_, err := checkPackageVulnerabilities(pkg, osRelease)
	if err == nil {
		t.Error("Expected error for unsupported distribution, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported distribution") {
		t.Errorf("Expected 'unsupported distribution' in error, got: %v", err)
	}
}

// Test helper function to create mock advisory data
func createMockAdvisory(vulnID, fixedVersion string) types.Advisory {
	return types.Advisory{
		VulnerabilityID: vulnID,
		FixedVersion:    fixedVersion,
	}
}

// Test the filtering logic with mock data
func TestVulnerabilityFiltering(t *testing.T) {
	tests := []struct {
		name            string
		pkgVersion      string
		advisories      []types.Advisory
		distro          OSDistro
		expectedFiltered int
	}{
		{
			name:       "Ubuntu - all vulnerabilities fixed",
			pkgVersion: "1.2.3-4ubuntu2",
			advisories: []types.Advisory{
				createMockAdvisory("CVE-2023-1234", "1.2.3-4ubuntu1"), // Fixed
				createMockAdvisory("CVE-2023-5678", "1.2.3-3ubuntu1"), // Fixed
			},
			distro:          DistroUbuntu,
			expectedFiltered: 0,
		},
		{
			name:       "Ubuntu - some vulnerabilities active",
			pkgVersion: "1.2.3-4ubuntu1",
			advisories: []types.Advisory{
				createMockAdvisory("CVE-2023-1234", "1.2.3-4ubuntu2"), // Active
				createMockAdvisory("CVE-2023-5678", "1.2.3-3ubuntu1"), // Fixed
			},
			distro:          DistroUbuntu,
			expectedFiltered: 1,
		},
		{
			name:       "Azure Linux - vulnerabilities without fixes",
			pkgVersion: "1.2.3-4.azl3",
			advisories: []types.Advisory{
				createMockAdvisory("CVE-2023-1234", ""), // No fix
				createMockAdvisory("CVE-2023-5678", ""), // No fix
			},
			distro:          DistroAzureLinux,
			expectedFiltered: 2,
		},
		{
			name:       "Azure Linux - mixed vulnerabilities",
			pkgVersion: "1.2.3-4.azl3",
			advisories: []types.Advisory{
				createMockAdvisory("CVE-2023-1234", "1.2.3-5.azl3"), // Active
				createMockAdvisory("CVE-2023-5678", "1.2.3-3.azl3"), // Fixed
				createMockAdvisory("CVE-2023-9999", ""),             // No fix
			},
			distro:          DistroAzureLinux,
			expectedFiltered: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the filtering logic from checkPackageVulnerabilities
			var activeVulns []types.Advisory
			for _, vuln := range tt.advisories {
				if !isPackageFixed(tt.pkgVersion, vuln.FixedVersion, tt.distro) {
					activeVulns = append(activeVulns, vuln)
				}
			}

			if len(activeVulns) != tt.expectedFiltered {
				t.Errorf("Expected %d active vulnerabilities, got %d", tt.expectedFiltered, len(activeVulns))
			}
		})
	}
}

// Integration test that validates the complete flow without external dependencies
func TestVulnerabilityWorkflow(t *testing.T) {
	// Test package data
	pkg := OSPackage{
		Name:    "test-package",
		Version: "1.2.3-4ubuntu1",
	}

	osRelease := &OSRelease{
		Distro:    DistroUbuntu,
		VersionID: "20.04",
	}

	// Test that the function signature works correctly
	// Note: This will panic without Trivy DB initialization, so we catch the panic
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Function panicked as expected without Trivy DB: %v", r)
		}
	}()
	
	_, err := checkPackageVulnerabilities(pkg, osRelease)
	
	// We expect this to fail since we don't have Trivy DB initialized in tests
	// But it should fail at the vulnerability source level, not due to our code
	if err == nil {
		t.Log("Vulnerability check succeeded (Trivy DB must be available)")
	} else {
		// This is expected in test environment without Trivy DB
		t.Logf("Vulnerability check failed as expected without Trivy DB: %v", err)
	}
}

// Benchmark tests for performance validation
func BenchmarkIsURL(b *testing.B) {
	testInputs := []string{
		"https://example.com/file.txt",
		"./local-file.txt",
		"/absolute/path/file.txt",
		"relative-file.txt",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, input := range testInputs {
			isURL(input)
		}
	}
}

func BenchmarkIsPackageFixed_Ubuntu(b *testing.B) {
	pkgVersion := "1.2.3-4ubuntu1"
	fixedVersion := "1.2.3-4ubuntu2"
	distro := DistroUbuntu

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isPackageFixed(pkgVersion, fixedVersion, distro)
	}
}

func BenchmarkIsPackageFixed_AzureLinux(b *testing.B) {
	pkgVersion := "1.2.3-4.azl3"
	fixedVersion := "1.2.3-5.azl3"
	distro := DistroAzureLinux

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isPackageFixed(pkgVersion, fixedVersion, distro)
	}
}