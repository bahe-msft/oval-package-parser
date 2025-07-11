# OVAL Package Parser

A Go-based parser for extracting installed packages and vulnerability information from VHD build output files. The tool leverages the Trivy vulnerability database to scan for security advisories across multiple Linux distributions.

## Features

- **Multi-distribution support**: Ubuntu/Debian, Azure Linux, and CBL-Mariner
- **Package parsing**: Extracts installed packages from VHD build outputs
- **Container image extraction**: Parses pre-pulled container images
- **OS release detection**: Identifies distribution and version information
- **Vulnerability scanning**: Checks for active CVEs using Trivy database
- **Version comparison**: Intelligent filtering of fixed vs unfixed vulnerabilities
- **Command line interface**: Supports both local files and remote URLs
- **High performance**: Optimized regex patterns with 4-6x speed improvements

## Installation

### Option 1: Go Install (Recommended)

```bash
# Install directly from repository
go install github.com/bahe-msft/oval-package-parser@latest

# The binary will be available in your $GOPATH/bin
oval-package-parser <file-or-url>
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone <repository-url>
cd oval-package-parser

# Build the binary
go build -o oval-package-parser main.go

# Or run directly
go run main.go <file-or-url>
```

## Usage

### Basic Usage

```bash
# Scan local VHD build output file
./oval-package-parser ./sample-ubuntu.txt

# Scan from remote URL
./oval-package-parser https://example.com/vhd-build-output.txt

# Example with CBL-Mariner data
./oval-package-parser https://raw.githubusercontent.com/Azure/AgentBaker/refs/heads/master/vhdbuilder/release-notes/AKSCBLMarinerV2/gen2/202507.06.0.txt
```

### Output Example

```
=== Container Images ===
mcr.microsoft.com/oss/kubernetes/pause:3.6
mcr.microsoft.com/containernetworking/azure-cni:v1.6.21

=== Packages with Vulnerabilities ===
Package: curl 8.5.0-2ubuntu10.6
  - CVE-2025-0167 (no fix available)

Package: kernel 5.15.182.1-1.cm2
  - CVE-2022-4543 (no fix available)

=== Vulnerability Scan Summary ===
Total packages scanned: 749
Packages with vulnerabilities: 2
Packages with fixable vulnerabilities: 0
Packages with unfixable vulnerabilities: 2
Total vulnerabilities found: 2
Fixable vulnerabilities: 0
Unfixable vulnerabilities: 2

=== OS Info ===
Distribution: Ubuntu/Debian
OS: Ubuntu 24.04.2 LTS (Noble Numbat)
```

## Supported Formats

### Package Formats

#### Ubuntu/Debian (APT)
```
adduser/noble,now 3.137ubuntu1 all [installed,automatic]
```

#### Azure Linux (RPM)
```
python3-cryptography-42.0.5-3.azl3.x86_64
```

#### CBL-Mariner (RPM)
```
filesystem-1.1-20.cm2.x86_64
```

### Container Images
```
containerd images pre-pulled:
  - mcr.microsoft.com/oss/kubernetes/pause:3.6
  - mcr.microsoft.com/containernetworking/azure-cni:v1.6.21
```

### OS Release Information
```
=== os-release Begin
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
PRETTY_NAME="Ubuntu 24.04.2 LTS"
ID=ubuntu
=== os-release End
```

## Development

### Prerequisites

- Go 1.21+
- Trivy vulnerability database (automatically downloaded)

### Build Commands

```bash
# Build executable
go build -o oval-parser main.go

# Run all tests
go test ./...

# Run tests with verbose output
go test -v

# Run performance benchmarks
go test -bench=.

# Run linting and formatting
go vet ./...
go fmt ./...

# Clean up dependencies
go mod tidy
```

### Testing

The project includes comprehensive test coverage:

```bash
# Run unit tests
go test -v

# Run with coverage
go test -cover

# Generate coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Performance

The parser is optimized for performance with pre-compiled regex patterns for fast package parsing across all supported distributions.

## Architecture

### Core Components

- **Parser**: Main parsing engine with pre-compiled regex patterns
- **Vulnerability Scanner**: Trivy database integration for CVE detection
- **Version Comparison**: Distribution-specific version handling
- **CLI Interface**: Command line argument processing and URL fetching

### Dependencies

- `github.com/aquasecurity/trivy-db`: Vulnerability database and querying
- `github.com/knqyf263/go-deb-version`: Debian/Ubuntu version comparison
- `github.com/knqyf263/go-rpm-version`: RPM version comparison
- Standard Go library: No external runtime dependencies

## API Usage

```go
package main

import (
    "fmt"
    "log"
)

func main() {
    // Create parser
    parser, err := NewParser()
    if err != nil {
        log.Fatal(err)
    }

    // Parse from file
    result, err := parser.ParseFromFile("./sample-ubuntu.txt")
    if err != nil {
        log.Fatal(err)
    }

    // Access parsed data
    fmt.Printf("Found %d packages\n", len(result.Packages))
    fmt.Printf("Found %d container images\n", len(result.ContainerImages))
    
    if result.OSRelease != nil {
        fmt.Printf("OS: %s %s\n", result.OSRelease.Name, result.OSRelease.Version)
    }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Go conventions and `gofmt` formatting
- Add tests for new functionality
- Update documentation for API changes
- Run `go vet` and `go test` before submitting

## Sample Data

The repository includes sample VHD build output files:

- `sample-ubuntu.txt`: Ubuntu 24.04 build with APT packages
- `sample-azlinux3.txt`: Azure Linux 3.0 build with RPM packages


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Trivy](https://github.com/aquasecurity/trivy) for vulnerability database
- [go-deb-version](https://github.com/knqyf263/go-deb-version) for Debian version comparison
- [go-rpm-version](https://github.com/knqyf263/go-rpm-version) for RPM version comparison