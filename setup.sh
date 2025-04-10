#!/bin/bash

echo "Setting up Microsoft STAC Proxy..."

# Initialize Go module if needed
if [ ! -f "go.mod" ]; then
    echo "Initializing Go module..."
    go mod init github.com/Youssef-Harby/ms-stac-proxy
fi

# Tidy module
echo "Tidying module..."
go mod tidy

# Create build directory if it doesn't exist
echo "Creating build directory..."
mkdir -p build

# Build the application for different platforms and architectures
echo "Building application for multiple platforms and architectures..."

# macOS (darwin)
echo "Building for macOS (x86_64)..."
GOOS=darwin GOARCH=amd64 go build -o build/ms-stac-proxy-darwin-amd64 main.go

echo "Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -o build/ms-stac-proxy-darwin-arm64 main.go

# Linux
echo "Building for Linux (x86_64)..."
GOOS=linux GOARCH=amd64 go build -o build/ms-stac-proxy-linux-amd64 main.go

echo "Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -o build/ms-stac-proxy-linux-arm64 main.go

# Windows
echo "Building for Windows (x86_64)..."
GOOS=windows GOARCH=amd64 go build -o build/ms-stac-proxy-windows-amd64.exe main.go

echo "Building for Windows (arm64)..."
GOOS=windows GOARCH=arm64 go build -o build/ms-stac-proxy-windows-arm64.exe main.go

echo "Setup complete!"
echo "All binaries are available in the 'build' directory."
