# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based OVAL (Open Vulnerability and Assessment Language) package parser that leverages the Trivy vulnerability database to extract security advisories for specific operating system versions and packages. The project includes an optimized package parser that can extract installed packages from VHD build output files supporting both Ubuntu/Debian (APT) and Azure Linux (RPM) package formats.

## Development Commands

### Build and Run
```bash
go run main.go                 # Run the vulnerability query tool
go build -o oval-parser main.go   # Build executable
./oval-parser                  # Run built executable
```

### Testing and Linting
```bash
go test ./...                  # Run all tests (30+ test cases)
go test -v                     # Run tests with verbose output
go test -bench=.               # Run performance benchmarks
go vet ./...                   # Static analysis
go fmt ./...                   # Format code
go mod tidy                    # Clean up dependencies
```

### Dependency Management
```bash
go mod download               # Download dependencies
go mod verify                 # Verify dependencies
go get -u ./...              # Update dependencies
```

## Architecture

### Core Components

- **main.go**: Entry point that initializes the Trivy database and demonstrates vulnerability querying for:
  - Azure Linux 3.0 with python3.12 package
  - Ubuntu 24.04 with python3.12 package

- **parser.go**: Optimized parser with the following features:
  - **Parser struct**: Pre-compiled regex patterns for performance (4-6x faster)
  - **Multiple input methods**: String, file, and io.Reader support
  - **Multi-format support**: Packages (Ubuntu/RPM), container images, and OS release info
  - **Rich metadata**: Parsing statistics and format information
  - **Error handling**: Comprehensive error types and context
  - **Clean API**: Focused, non-deprecated interface

- **parser_test.go**: Comprehensive test suite with 25+ test cases including:
  - Unit tests for all parsing functions
  - Edge case testing
  - Error condition testing
  - Performance benchmarks

### Package Parser Usage

```go
// Modern API (recommended)
parser, err := NewParser()
if err != nil {
    log.Fatal(err)
}

result, err := parser.ParseInstalledPackages(content)
if err != nil {
    log.Printf("Parsing failed: %v", err)
    return
}

fmt.Printf("Found %d packages\n", len(result.Packages))
fmt.Printf("Found %d container images\n", len(result.ContainerImages))
if result.OSRelease != nil {
    fmt.Printf("OS: %s\n", result.OSRelease.Distro)
}

// That's it! Clean, simple API
```

### Supported Data Formats

#### 1. Packages
- **Ubuntu/Debian (APT)**: `package/source,now version arch [status]`
  - Example: `adduser/noble,now 3.137ubuntu1 all [installed,automatic]`
- **Azure Linux (RPM)**: `package-version-release.dist.arch`
  - Example: `python3-cryptography-42.0.5-3.azl3.x86_64`

#### 2. Container Images
- **Format**: `  - registry/repository:tag`
- **Section**: `containerd images pre-pulled:`
- **Examples**:
  - `mcr.microsoft.com/oss/kubernetes/pause:3.6`
  - `mcr.microsoft.com/containernetworking/azure-cni:v1.4.59`
  - `mcr.microsoft.com/oss/v2/kubernetes/autoscaler/addon-resizer:v1.8.23-2`

#### 3. OS Release Information
- **Section**: `=== os-release Begin/End`
- **Fields**: NAME, VERSION_ID, VERSION, PRETTY_NAME, ID
- **Example**: `NAME="Microsoft Azure Linux"`

### Data Flow

1. Initialize Trivy database from local cache
2. Create vulnerability source instances for target OS distributions
3. Query advisories using OS version and package name
4. Parse installed packages from VHD build output files
5. Output structured vulnerability and package information

### Sample Data Files

- `sample-azlinux3.txt`: Example Azure Linux 3.0 build with RPM package listings
- `sample-ubuntu.txt`: Example Ubuntu build with APT package listings

These files contain VHD build component information including:
- Installed packages between `=== Installed Packages Begin/End` markers
- Pre-pulled container images in the `containerd images pre-pulled:` section  
- OS release information between `=== os-release Begin/End` markers

## Key Dependencies

- **trivy-db**: Core vulnerability database and querying functionality
- **Standard library**: regexp, bufio, strings, errors, fmt, io, os
- **No external dependencies**: Uses only Go standard library for parsing

## Performance Characteristics

The optimized parser provides significant performance improvements:
- **Ubuntu package parsing**: 4.27x faster (1,865 ns/op vs 7,967 ns/op)
- **RPM package parsing**: 6.32x faster (3,621 ns/op vs 22,902 ns/op)
- **Full package list parsing**: 4.39x faster (14,661 ns/op vs 64,343 ns/op)

## Error Handling

The package parser uses comprehensive error handling:
- **Custom error types**: `ErrNoPackageSection` for specific conditions
- **Error wrapping**: Context-aware error messages with `fmt.Errorf`
- **Input validation**: Proper validation of all inputs
- **Resource management**: Proper file handling and cleanup

The main vulnerability query tool uses a simple `fatalIfErr()` function for demonstration purposes.