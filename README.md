# Microsoft Planetary Computer STAC Proxy

A lightweight, efficient proxy for the Microsoft Planetary Computer STAC API that handles authentication tokens automatically.

## Features

- **Direct Proxy**: Transparently forwards requests to the Microsoft Planetary Computer API
- **Automatic Collection Detection**: Detects collection IDs from URLs and response content
- **Smart Token Management**: Automatically fetches and caches SAS tokens for each collection
- **Persistent Token Caching**: Saves tokens to disk to prevent rate limiting even between restarts
- **URL Rewriting**: Properly signs Azure blob URLs with the appropriate SAS tokens
- **Compression Support**: Handles gzip and brotli compressed responses

## How It Works

This proxy sits between your client application and the Microsoft Planetary Computer API. It:

1. Intercepts requests to the STAC API
2. Forwards them to the Microsoft Planetary Computer
3. Detects which collection is being requested (with fallback to "default-collection" if none is found)
4. Fetches and caches appropriate SAS tokens
5. Transforms responses by signing Azure blob URLs (excluding public assets storage)
6. Returns the modified response to the client

The proxy includes a visual dashboard-style startup display showing key information like the STAC API URL, GitHub repository, and target API.

## Setup

### Prerequisites

- Go 1.16 or later

### Installation

1. Clone the repository
2. Run the setup script to download dependencies:

```bash
chmod +x setup.sh
./setup.sh
```

### Running the Proxy

Start the proxy:

```bash
go run main.go
```

You can specify a custom port using the `-p` flag:

```bash
go run main.go -p 8081
```

Or use the compiled binary after running the setup script:

```bash
./ms-stac-proxy
./ms-stac-proxy -p 8081  # Custom port
```

By default, the proxy runs on port 8080 and provides a clear dashboard-style startup display with information about:
- The STAC API URL (http://localhost:8080/api/stac/v1)
- The GitHub repository link
- The target Microsoft Planetary Computer API endpoint
- Token cache file location

### Using Docker

You can also run the proxy using Docker:

```bash
# Pull the image from GitHub Container Registry
docker pull ghcr.io/youssef-harby/ms-stac-proxy:latest

# Run the container
docker run -p 8080:8080 ghcr.io/youssef-harby/ms-stac-proxy:latest

# Or specify a custom port
docker run -p 8081:8080 ghcr.io/youssef-harby/ms-stac-proxy:latest
```

If you want to build the Docker image locally:

```bash
# Build the image
docker build -t ms-stac-proxy .

# Run the container
docker run -p 8080:8080 ms-stac-proxy
```

The Docker image includes all the fixes for CORS handling and token issues, ensuring proper URL signing for all supported collections.

### Using Prebuilt Binaries

You can download prebuilt binaries for your operating system from the [GitHub Releases page](https://github.com/Youssef-Harby/ms-stac-proxy/releases).

1. Navigate to the [Releases page](https://github.com/Youssef-Harby/ms-stac-proxy/releases)
2. Download the appropriate binary for your system:
   - macOS (Intel): `ms-stac-proxy-darwin-amd64.tar.gz`
   - macOS (Apple Silicon): `ms-stac-proxy-darwin-arm64.tar.gz`
   - Linux (x86_64): `ms-stac-proxy-linux-amd64.tar.gz`
   - Linux (ARM64): `ms-stac-proxy-linux-arm64.tar.gz`
   - Windows (x86_64): `ms-stac-proxy-windows-amd64.zip`
   - Windows (ARM64): `ms-stac-proxy-windows-arm64.zip`

#### Note for macOS Users

macOS may block the binary from running due to security restrictions. If you receive a "killed" message when trying to run the binary, use the following command to remove the security attribute:

```bash
xattr -cr ms-stac-proxy-darwin-arm64
# or for Intel Macs
xattr -cr ms-stac-proxy-darwin-amd64
```

Then you can run the binary normally:

```bash
./ms-stac-proxy-darwin-arm64
```

## Releases

This project uses GitHub Actions to automatically build and release binaries for multiple platforms when a new tag is pushed. The workflow:

1. Builds binaries for:
   - macOS (x86_64 and arm64)
   - Linux (x86_64 and arm64) 
   - Windows (x86_64 and arm64)
2. Packages the binaries (tar.gz for macOS/Linux, zip for Windows)
3. Creates a GitHub release with the binaries attached

### Creating a Release

To create a new release:

```bash
# Create a tag
git tag v1.0.0

# Push the tag to GitHub
git push origin v1.0.0
```

The GitHub Actions workflow will automatically build and publish the release.

### Deleting and Re-Creating a Release

If you need to delete a tag and re-create it:

```bash
# Delete the tag locally
git tag -d v1.0.0

# Delete the tag remotely
git push --delete origin v1.0.0

# Re-create the tag
git tag v1.0.0

# Push the new tag
git push origin v1.0.0
```

## Usage

Once the proxy is running, configure your client application to use `http://localhost:8080` as the base URL for the Microsoft Planetary Computer API.

For example, to access the collections endpoint:

```
http://localhost:8080/api/stac/v1/collections
```

The proxy will automatically:

1. Forward your request to `https://planetarycomputer.microsoft.com/api/stac/v1/collections`
2. Cache the appropriate tokens for each collection
3. Sign all Azure blob URLs in the response
4. Return the processed response to your client

## Token Handling and URL Signing

The proxy handles authentication to Microsoft Planetary Computer by:

- Automatically detecting collection IDs from request paths and response content
- Fetching SAS tokens for the appropriate collection
- Caching tokens in memory and on disk to minimize API calls
- Intelligently signing Azure blob URLs with the correct token
- Using a fallback "default-collection" when no specific collection is detected
- Skipping token signing for public storage accounts (ai4edatasetspublicassets.blob.core.windows.net)

This approach eliminates the need to manually manage tokens in your application.

## CORS Support

The proxy handles Cross-Origin Resource Sharing (CORS) automatically by:

- Setting permissive CORS headers on all responses
- Allowing requests from any origin
- Handling preflight requests properly
- Skipping duplicate CORS headers from upstream responses

This makes it easy to use the API directly from web applications without CORS issues.

## Token Caching

Tokens are cached in memory and persisted to disk in `token_cache.json`. This allows the proxy to:

- Minimize API calls to the token service
- Prevent rate limiting issues
- Maintain token availability between proxy restarts
- Automatically refresh tokens when they expire

## Configuration

The proxy can be configured using command-line flags or environment variables:

### Command-line flags:
- `-p <port>`: Set the proxy port (e.g., `-p 8081`)

### Environment variables:
- `PROXY_PORT`: The port the proxy listens on (default: 8080)
- `TARGET_BASE_URL`: The base URL of the Microsoft Planetary Computer API (default: https://planetarycomputer.microsoft.com)
- `TOKEN_ENDPOINT`: The endpoint for fetching SAS tokens (default: https://planetarycomputer.microsoft.com/api/sas/v1/token)
- `TOKEN_CACHE_FILE`: The file where tokens are persisted (default: token_cache.json)
- `REQUEST_TIMEOUT`: Timeout for HTTP requests (default: 60s)
- `SAVE_PERIOD`: How often to save tokens to disk (default: 5m)
- `RETRY_ATTEMPTS`: Number of retry attempts for failed requests (default: 3)
- `RETRY_DELAY`: Delay between retry attempts (default: 500ms)

Note: Command-line flags take precedence over environment variables.

## License

[MIT License](LICENSE)
