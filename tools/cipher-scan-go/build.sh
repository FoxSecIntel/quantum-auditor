#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building cipher-scan for Linux amd64"
GOOS=linux GOARCH=amd64 go build -o cipher-scan main.go

echo "Building cipher-scan.exe for Windows amd64"
GOOS=windows GOARCH=amd64 go build -o cipher-scan.exe main.go

echo "Done"
