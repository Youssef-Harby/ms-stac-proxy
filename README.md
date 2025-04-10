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
3. Detects which collection is being requested
4. Fetches and caches appropriate SAS tokens
5. Transforms responses by signing Azure blob URLs
6. Returns the modified response to the client

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
go run direct-proxy.go
```

Or use the compiled binary after running the setup script:

```bash
./ms-stac-proxy
```

By default, the proxy runs on port 8080.

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

## Token Caching

Tokens are cached in memory and persisted to disk in `token_cache.json`. This allows the proxy to:

- Minimize API calls to the token service
- Prevent rate limiting issues
- Maintain token availability between proxy restarts
- Automatically refresh tokens when they expire

## Configuration

Configuration options are defined as constants in the source code:

- `proxyPort`: The port the proxy listens on (default: 8080)
- `targetBaseURL`: The base URL of the Microsoft Planetary Computer API
- `tokenEndpoint`: The endpoint for fetching SAS tokens
- `tokenCacheFile`: The file where tokens are persisted
- `defaultTimeout`: Default timeout for HTTP requests
- `savePeriod`: How often to save tokens to disk (also saved immediately upon fetching new tokens)

## License

[MIT License](LICENSE)
