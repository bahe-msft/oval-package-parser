package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/azure"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
)

func fatalIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

// isURL checks if the input string is a URL
func isURL(input string) bool {
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

// fetchContent fetches content from either a URL or local file
func fetchContent(source string) (io.Reader, error) {
	if isURL(source) {
		fmt.Printf("Fetching content from URL: %s\n", source)
		resp, err := http.Get(source)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch URL %s: %v", source, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP error %d when fetching %s", resp.StatusCode, source)
		}
		return resp.Body, nil
	} else {
		fmt.Printf("Reading local file: %s\n", source)
		file, err := os.Open(source)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %v", source, err)
		}
		return file, nil
	}
}

// isPackageFixed checks if a package version is fixed based on the fixed version
// Uses appropriate version comparison for the OS distribution
func isPackageFixed(pkgVersion, fixedVersion string, distro OSDistro) bool {
	if fixedVersion == "" {
		return false // No fix available
	}

	switch distro {
	case DistroUbuntu:
		pkgVer, err := debversion.NewVersion(pkgVersion)
		if err != nil {
			return false
		}
		fixedVer, err := debversion.NewVersion(fixedVersion)
		if err != nil {
			return false
		}
		return pkgVer.Compare(fixedVer) >= 0
	case DistroAzureLinux, DistroMariner:
		pkgVer := rpmversion.NewVersion(pkgVersion)
		fixedVer := rpmversion.NewVersion(fixedVersion)
		return pkgVer.Compare(fixedVer) >= 0
	default:
		return false
	}
}

// checkPackageVulnerabilities checks for vulnerabilities in a given package
// based on the OS distribution and version. Returns only unfixed vulnerabilities.
func checkPackageVulnerabilities(pkg OSPackage, osRelease *OSRelease) ([]types.Advisory, error) {
	if osRelease == nil {
		return nil, fmt.Errorf("OS release information required for vulnerability checking")
	}

	var allVulns []types.Advisory
	var err error

	switch osRelease.Distro {
	case DistroUbuntu:
		vulnSrc := ubuntu.NewVulnSrc()
		allVulns, err = vulnSrc.Get(osRelease.VersionID, pkg.Name)
	case DistroAzureLinux:
		vulnSrc := azure.NewVulnSrc(azure.Azure)
		allVulns, err = vulnSrc.Get(osRelease.VersionID, pkg.Name)
	case DistroMariner:
		vulnSrc := azure.NewVulnSrc(azure.Mariner)
		allVulns, err = vulnSrc.Get(osRelease.VersionID, pkg.Name)
	default:
		return nil, fmt.Errorf("unsupported distribution: %s", osRelease.Distro)
	}

	if err != nil {
		return nil, err
	}

	// Filter out fixed vulnerabilities
	var activeVulns []types.Advisory
	for _, vuln := range allVulns {
		if !isPackageFixed(pkg.Version, vuln.FixedVersion, osRelease.Distro) {
			activeVulns = append(activeVulns, vuln)
		}
	}

	return activeVulns, nil
}

func main() {
	// Check command line arguments
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file-path-or-url>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s ./sample-ubuntu.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s https://example.com/vhd-build-output.txt\n", os.Args[0])
		os.Exit(1)
	}

	source := os.Args[1]
	
	p, err := NewParser()
	fatalIfErr(err)

	// Fetch content from source (file or URL)
	reader, err := fetchContent(source)
	fatalIfErr(err)
	defer func() {
		if closer, ok := reader.(io.Closer); ok {
			closer.Close()
		}
	}()

	// Parse the content
	d, err := p.Parse(reader)
	fatalIfErr(err)

	// Initialize Trivy vulnerability database
	homeDir := os.Getenv("HOME")
	fatalIfErr(db.Init(homeDir + "/.cache/trivy/db"))

	fmt.Println("=== Container Images ===")
	for _, img := range d.ContainerImages {
		fmt.Println(img.Name)
	}

	// Vulnerability scanning summary counters
	totalPackages := len(d.Packages)
	packagesWithVulns := 0
	packagesWithFixableVulns := 0
	packagesWithUnfixableVulns := 0
	totalVulns := 0
	fixableVulns := 0
	unfixableVulns := 0

	fmt.Println("\n=== Packages with Vulnerabilities ===")

	if d.OSRelease == nil {
		fmt.Println("Unable to check vulnerabilities (no OS release info)")
	} else {
		for _, pkg := range d.Packages {
			vulns, err := checkPackageVulnerabilities(pkg, d.OSRelease)
			if err != nil {
				fmt.Printf("Package: %s %s - Error: %v\n", pkg.Name, pkg.Version, err)
				continue
			}

			// Only show packages with vulnerabilities
			if len(vulns) > 0 {
				fmt.Printf("Package: %s %s\n", pkg.Name, pkg.Version)
				packagesWithVulns++
				totalVulns += len(vulns)

				hasFixable := false
				hasUnfixable := false

				for _, vuln := range vulns {
					if vuln.FixedVersion != "" {
						fmt.Printf("  - %s (needs upgrade to: %s)\n", vuln.VulnerabilityID, vuln.FixedVersion)
						fixableVulns++
						hasFixable = true
					} else {
						fmt.Printf("  - %s (no fix available)\n", vuln.VulnerabilityID)
						unfixableVulns++
						hasUnfixable = true
					}
				}

				if hasFixable {
					packagesWithFixableVulns++
				}
				if hasUnfixable {
					packagesWithUnfixableVulns++
				}

				fmt.Println()
			}
		}
	}

	// Print summary
	fmt.Println("=== Vulnerability Scan Summary ===")
	fmt.Printf("Total packages scanned: %d\n", totalPackages)
	fmt.Printf("Packages with vulnerabilities: %d\n", packagesWithVulns)
	fmt.Printf("Packages with fixable vulnerabilities: %d\n", packagesWithFixableVulns)
	fmt.Printf("Packages with unfixable vulnerabilities: %d\n", packagesWithUnfixableVulns)
	fmt.Printf("Total vulnerabilities found: %d\n", totalVulns)
	fmt.Printf("Fixable vulnerabilities: %d\n", fixableVulns)
	fmt.Printf("Unfixable vulnerabilities: %d\n", unfixableVulns)

	if d.OSRelease != nil {
		fmt.Printf("\n=== OS Info ===\n")
		fmt.Printf("Distribution: %s\n", d.OSRelease.Distro)
		fmt.Printf("OS: %s %s (%s)\n", d.OSRelease.Name, d.OSRelease.Version, d.OSRelease.VersionID)
	}
}
