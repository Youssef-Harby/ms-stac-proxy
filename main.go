/*
 * Microsoft STAC Proxy
 *
 * Author: Youssef Harby
 * GitHub: https://github.com/Youssef-Harby/ms-stac-proxy
 *
 * A proxy server for Microsoft Planetary Computer STAC API with token handling
 * and CORS support for simplified client-side access to geospatial data.
 */

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
)

const (
	defaultProxyPort      = 8080
	defaultTargetBaseURL  = "https://planetarycomputer.microsoft.com"
	defaultTokenEndpoint  = "https://planetarycomputer.microsoft.com/api/sas/v1/token"
	defaultTokenCacheFile = "token_cache.json"
	defaultTimeout        = 60 * time.Second
	defaultSavePeriod     = 5 * time.Minute
	defaultRetryAttempts  = 3
	defaultRetryDelay     = 500 * time.Millisecond
)

const (
	headerContentType     = "Content-Type"
	headerContentEncoding = "Content-Encoding"
	headerContentLength   = "Content-Length"
	headerHost            = "Host"
	headerUserAgent       = "User-Agent"
	headerAccept          = "Accept"
	headerXForwardedFor   = "X-Forwarded-For"
	headerXForwardedHost  = "X-Forwarded-Host"
)

const (
	statusOK                  = http.StatusOK
	statusBadRequest          = http.StatusBadRequest
	statusInternalServerError = http.StatusInternalServerError
	statusBadGateway          = http.StatusBadGateway
)

type Config struct {
	ProxyPort      int
	TargetBaseURL  string
	TokenEndpoint  string
	TokenCacheFile string
	Timeout        time.Duration
	SavePeriod     time.Duration
	RetryAttempts  int
	RetryDelay     time.Duration
}

type TokenResponse struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"msft:expiry"`
}

type TokenCache struct {
	mu           sync.RWMutex
	tokens       map[string]TokenResponse
	lastSaveTime time.Time
	dirty        bool // Indicates if there are unsaved changes
}

var (
	config Config

	tokenCache = TokenCache{
		tokens:       make(map[string]TokenResponse),
		lastSaveTime: time.Now(),
	}

	httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     1000,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false, // Allow compression
			ForceAttemptHTTP2:   true,  // Attempt HTTP/2
		},
	}

	collectionPathRegex = regexp.MustCompile(`/collections/([^/?#]+)`)
	blobURLRegex        = regexp.MustCompile(`https://([^\.]+)\.blob\.core\.windows\.net/([^/]+)/([^"?\s]+)`)

	shutdownCh = make(chan struct{})
)

func loadConfig() Config {
	cfg := Config{
		ProxyPort:      defaultProxyPort,
		TargetBaseURL:  defaultTargetBaseURL,
		TokenEndpoint:  defaultTokenEndpoint,
		TokenCacheFile: defaultTokenCacheFile,
		Timeout:        defaultTimeout,
		SavePeriod:     defaultSavePeriod,
		RetryAttempts:  defaultRetryAttempts,
		RetryDelay:     defaultRetryDelay,
	}

	if port := os.Getenv("PROXY_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil && p > 0 {
			cfg.ProxyPort = p
		}
	}

	if url := os.Getenv("TARGET_BASE_URL"); url != "" {
		cfg.TargetBaseURL = url
	}

	if endpoint := os.Getenv("TOKEN_ENDPOINT"); endpoint != "" {
		cfg.TokenEndpoint = endpoint
	}

	if cacheFile := os.Getenv("TOKEN_CACHE_FILE"); cacheFile != "" {
		cfg.TokenCacheFile = cacheFile
	}

	if timeout := os.Getenv("REQUEST_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.Timeout = d
		}
	}

	if savePeriod := os.Getenv("SAVE_PERIOD"); savePeriod != "" {
		if d, err := time.ParseDuration(savePeriod); err == nil {
			cfg.SavePeriod = d
		}
	}

	if retries := os.Getenv("RETRY_ATTEMPTS"); retries != "" {
		if r, err := strconv.Atoi(retries); err == nil && r >= 0 {
			cfg.RetryAttempts = r
		}
	}

	if delay := os.Getenv("RETRY_DELAY"); delay != "" {
		if d, err := time.ParseDuration(delay); err == nil {
			cfg.RetryDelay = d
		}
	}

	httpClient.Timeout = cfg.Timeout

	return cfg
}

func main() {
	config = loadConfig()

	stacAPIURL := fmt.Sprintf("http://localhost:%d/api/stac/v1", config.ProxyPort)
	targetStacAPI := fmt.Sprintf("%s/api/stac/v1", config.TargetBaseURL)

	log.Printf("##############################################################")
	log.Printf("# Microsoft STAC Proxy Service Started                       #")
	log.Printf("# STAC API URL: %-43s #", stacAPIURL)
	log.Printf("# GitHub Repository: %-38s #", "https://github.com/Youssef-Harby/ms-stac-proxy")
	log.Printf("# Target API: %-45s #", targetStacAPI)
	log.Printf("# Token cache file: %-39s #", config.TokenCacheFile)
	log.Printf("##############################################################")

	loadTokenCache()

	cacheSaverDone := make(chan struct{})
	go startTokenCacheSaver(cacheSaverDone)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	mux := http.NewServeMux()
	mux.HandleFunc("/", corsMiddleware(handleProxyRequest))

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", config.ProxyPort),
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Server bound to all interfaces (0.0.0.0) on port %d", config.ProxyPort)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %v", err)
		}
	}()

	<-sigChan
	log.Println("Shutdown signal received, shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	close(shutdownCh)
	close(cacheSaverDone)

	if err := saveTokenCache(); err != nil {
		log.Printf("Error saving token cache during shutdown: %v", err)
	}

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}

func startTokenCacheSaver(done <-chan struct{}) {
	ticker := time.NewTicker(config.SavePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := saveTokenCache(); err != nil {
				log.Printf("Error saving token cache: %v", err)
			}
		case <-done:
			log.Println("Token cache saver stopped")
			return
		case <-shutdownCh:
			return
		}
	}
}

func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)

	collection := extractCollection(r.URL.Path)
	if collection != "" {
		log.Printf("Detected collection: %s", collection)
	}

	targetURL := fmt.Sprintf("%s%s", config.TargetBaseURL, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL = fmt.Sprintf("%s?%s", targetURL, r.URL.RawQuery)
	}

	ctx, cancel := context.WithTimeout(r.Context(), config.Timeout)
	defer cancel()

	var proxyReq *http.Request
	var err error

	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", statusInternalServerError)
			log.Printf("Error reading request body: %v", err)
			return
		}
		r.Body.Close()

		proxyReq, err = http.NewRequestWithContext(ctx, r.Method, targetURL, bytes.NewReader(bodyBytes))
		if err != nil {
			http.Error(w, "Error creating request", statusInternalServerError)
			log.Printf("Error creating request: %v", err)
			return
		}
	} else {
		proxyReq, err = http.NewRequestWithContext(ctx, r.Method, targetURL, nil)
		if err != nil {
			http.Error(w, "Error creating request", statusInternalServerError)
			log.Printf("Error creating request: %v", err)
			return
		}
	}

	for name, values := range r.Header {
		if name == headerHost {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(name, value)
		}
	}

	proxyReq.Header.Set(headerXForwardedFor, r.RemoteAddr)
	proxyReq.Header.Set(headerXForwardedHost, r.Host)

	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		http.Error(w, "Error forwarding request", statusBadGateway)
		log.Printf("Error forwarding request: %v", err)
		return
	}
	defer resp.Body.Close()

	if isSTACResponse(resp) {
		transformedResp, err := transformSTACResponse(resp, collection, r.Host)
		if err != nil {
			http.Error(w, "Error transforming response", statusInternalServerError)
			log.Printf("Error transforming response: %v", err)
			return
		}
		resp = transformedResp
	}

	// Copy response headers to client response, excluding CORS headers which are set by the middleware
	for name, values := range resp.Header {
		// Skip CORS headers as they're handled by our corsMiddleware
		if strings.HasPrefix(strings.ToLower(name), "access-control-") {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	bodyBytes, _ := io.ReadAll(resp.Body)
	if len(bodyBytes) == 0 {
		log.Printf("Warning: Empty response body after transformation")
	} else {
		log.Printf("Response body length: %d bytes", len(bodyBytes))
	}

	_, err = w.Write(bodyBytes)
	if err != nil {
		log.Printf("Error writing response body: %v", err)
	}

	log.Printf("Successfully proxied request: %s %s -> %d", r.Method, r.URL.Path, resp.StatusCode)
}

func isSTACResponse(resp *http.Response) bool {
	contentType := resp.Header.Get(headerContentType)
	return strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/geo+json") ||
		strings.Contains(contentType, "application/stac") ||
		strings.Contains(contentType, "application/ld+json")
}

func transformSTACResponse(resp *http.Response, collectionID string, hostHeader string) (*http.Response, error) {
	contentType := resp.Header.Get(headerContentType)
	contentEncoding := resp.Header.Get(headerContentEncoding)

	log.Printf("Transforming STAC response with Content-Type: %s, Content-Encoding: %s", contentType, contentEncoding)

	var reader io.ReadCloser
	var err error

	switch contentEncoding {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		defer reader.Close()
	case "br":
		reader = io.NopCloser(brotli.NewReader(resp.Body))
	default:
		reader = resp.Body
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	bodyStr := string(bodyBytes)

	// If we don't have a collection ID yet, try to extract it from the response
	if collectionID == "" {
		collectionID = findCollectionInResponse(bodyStr)
		if collectionID != "" {
			log.Printf("Using collection '%s' for token fetching", collectionID)
		}
	}

	// Sign all blob URLs regardless of collection
	if strings.Contains(bodyStr, ".blob.core.windows.net") {
		token, err := getTokenCached(collectionID)
		if err != nil {
			log.Printf("Error getting token for collection %s: %v", collectionID, err)
		} else {
			bodyStr = signBlobURLs(bodyStr, token)
		}
	}

	// Detect protocol from forwarded headers or default to http
	scheme := "http"

	// Check for common forwarded protocol headers
	forwardedProto := resp.Request.Header.Get("X-Forwarded-Proto")
	if forwardedProto != "" {
		scheme = forwardedProto
	}

	// Alternative header sometimes used
	forwardedScheme := resp.Request.Header.Get("X-Forwarded-Scheme")
	if forwardedScheme != "" {
		scheme = forwardedScheme
	}

	// If Host contains a port, keep it in the URL
	host := hostHeader

	// Use the host and detected protocol from the request
	proxyBaseURL := fmt.Sprintf("%s://%s", scheme, host)
	log.Printf("Using request host for URL replacement: %s", proxyBaseURL)
	bodyStr = strings.ReplaceAll(bodyStr, config.TargetBaseURL, proxyBaseURL)

	newResp := *resp
	newResp.Header = resp.Header.Clone()
	newResp.Body = io.NopCloser(strings.NewReader(bodyStr))
	newResp.ContentLength = int64(len(bodyStr))
	newResp.Header.Set(headerContentLength, fmt.Sprintf("%d", len(bodyStr)))
	newResp.Header.Del(headerContentEncoding)

	return &newResp, nil
}

func findCollectionInResponse(content string) string {
	// Try parsing as JSON first to get the collection ID
	var stacDoc map[string]interface{}
	if err := json.Unmarshal([]byte(content), &stacDoc); err == nil {
		// Check for direct collection property
		if collID, ok := stacDoc["collection"].(string); ok && collID != "" {
			return collID
		}

		// Check if this is a collection itself with an ID
		if collID, ok := stacDoc["id"].(string); ok && collID != "" {
			return collID
		}

		// Check in features array if this is a FeatureCollection
		if features, ok := stacDoc["features"].([]interface{}); ok && len(features) > 0 {
			if feature, ok := features[0].(map[string]interface{}); ok {
				if collID, ok := feature["collection"].(string); ok && collID != "" {
					return collID
				}
			}
		}
	}

	// If we couldn't parse JSON or couldn't find collection ID in JSON, try regex
	matches := collectionPathRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}

	// If we still don't have a collection ID, use a default
	// This is a simple failsafe - the blob URLs will still get signed regardless
	return "default-collection"
}

func extractCollection(path string) string {
	collectionMatch := collectionPathRegex.FindStringSubmatch(path)
	if len(collectionMatch) > 1 {
		return collectionMatch[1]
	}
	return ""
}

func getTokenCached(collection string) (string, error) {
	tokenCache.mu.RLock()
	cachedToken, exists := tokenCache.tokens[collection]
	tokenCache.mu.RUnlock()

	if exists && time.Now().Before(cachedToken.Expiry) {
		log.Printf("Using cached token for %s (expires in %v)",
			collection, cachedToken.Expiry.Sub(time.Now()).Round(time.Second))
		return cachedToken.Token, nil
	}

	var tokenResp TokenResponse
	var err error

	for attempt := 0; attempt < config.RetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * config.RetryDelay
			log.Printf("Retrying token fetch for %s (attempt %d/%d) after %v",
				collection, attempt+1, config.RetryAttempts, backoff)
			select {
			case <-time.After(backoff):
				// Continue with retry
			case <-shutdownCh:
				return "", fmt.Errorf("shutdown in progress")
			}
		}

		tokenResp, err = fetchToken(collection)
		if err == nil {
			break
		}

		if !isRetryableError(err) {
			break
		}
	}

	if err != nil {
		return "", err
	}

	tokenCache.mu.Lock()
	tokenCache.tokens[collection] = tokenResp
	tokenCache.dirty = true
	tokenCache.mu.Unlock()

	go func() {
		if err := saveTokenCache(); err != nil {
			log.Printf("Error saving token cache: %v", err)
		} else {
			log.Printf("Saved token cache with %d entries to %s", len(tokenCache.tokens), config.TokenCacheFile)
		}
	}()

	return tokenResp.Token, nil
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	if strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "no such host") ||
		strings.Contains(err.Error(), "network") {
		return true
	}

	if strings.Contains(err.Error(), "status code: 5") {
		return true
	}

	return false
}

func fetchToken(collection string) (TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/%s", config.TokenEndpoint, collection)
	log.Printf("Fetching fresh token from %s", tokenURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set(headerUserAgent, "STACProxy/1.0")
	req.Header.Set(headerAccept, "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sending token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return TokenResponse{}, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token        string    `json:"token"`
		ExpiryString string    `json:"msft:expiry"`
		Expiry       time.Time `json:"-"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return TokenResponse{}, fmt.Errorf("decoding token response: %w", err)
	}

	parsedExpiry, err := time.Parse(time.RFC3339, tokenResp.ExpiryString)
	if err != nil {
		parsedExpiry = time.Now().Add(1 * time.Hour)
		log.Printf("Warning: Could not parse token expiry time %q: %v. Using default expiration.", tokenResp.ExpiryString, err)
	}

	log.Printf("Token obtained for %s (expires: %s)", collection, parsedExpiry.Format(time.RFC3339))

	return TokenResponse{
		Token:  tokenResp.Token,
		Expiry: parsedExpiry,
	}, nil
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from any origin
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Allow all headers and methods
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		// Maximum permissive age
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Expose all headers
		w.Header().Set("Access-Control-Expose-Headers", "*")

		// For mixed content handling - extremely permissive
		w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
		w.Header().Set("Cross-Origin-Opener-Policy", "unsafe-none")
		w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")

		// To bypass mixed content restrictions
		w.Header().Set("Content-Security-Policy", "upgrade-insecure-requests")

		// For iframe embedding
		w.Header().Set("X-Frame-Options", "ALLOWALL")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func loadTokenCache() {
	file, err := os.Open(config.TokenCacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("No token cache file found at %s, will create when tokens are fetched", config.TokenCacheFile)
			return
		}
		log.Printf("Error opening token cache file: %v", err)
		return
	}
	defer file.Close()

	var loadedTokens map[string]TokenResponse
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&loadedTokens); err != nil {
		log.Printf("Error decoding token cache: %v", err)
		return
	}

	now := time.Now()
	validTokens := 0
	expiredTokens := 0

	tokenCache.mu.Lock()
	for collection, token := range loadedTokens {
		if now.Before(token.Expiry) {
			tokenCache.tokens[collection] = token
			validTokens++
		} else {
			expiredTokens++
		}
	}
	tokenCache.mu.Unlock()

	log.Printf("Loaded %d valid tokens from cache (discarded %d expired)", validTokens, expiredTokens)
}

func saveTokenCache() error {
	tokenCache.mu.RLock()
	if !tokenCache.dirty {
		tokenCache.mu.RUnlock()
		return nil
	}

	tokenCopy := make(map[string]TokenResponse)
	for k, v := range tokenCache.tokens {
		tokenCopy[k] = v
	}
	tokenCache.mu.RUnlock()

	dir := filepath.Dir(config.TokenCacheFile)
	if dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory for token cache: %w", err)
		}
	}

	tempFile := config.TokenCacheFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("creating token cache file: %w", err)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(tokenCopy); err != nil {
		file.Close()
		return fmt.Errorf("encoding token cache: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("closing token cache file: %w", err)
	}

	if err := os.Rename(tempFile, config.TokenCacheFile); err != nil {
		return fmt.Errorf("renaming token cache file: %w", err)
	}

	tokenCache.mu.Lock()
	tokenCache.dirty = false
	tokenCache.lastSaveTime = time.Now()
	tokenCache.mu.Unlock()

	log.Printf("Saved %d tokens to cache file", len(tokenCopy))
	return nil
}

func signBlobURLs(content, token string) string {
	// Simple regex to detect all blob URLs that don't already have query parameters
	blobURLRegex := regexp.MustCompile(`https://[^\.]+\.blob\.core\.windows\.net/[^"'\s?]+`)

	// Find all matches in the content
	matches := blobURLRegex.FindAllString(content, -1)
	if len(matches) == 0 {
		return content
	}

	modifiedContent := content
	signedCount := 0

	for _, originalURL := range matches {
		// Skip URLs that already have a signature (containing '?')
		if strings.Contains(originalURL, "?") {
			continue
		}

		// Skip specific storage accounts that don't need signing or have different auth
		if strings.Contains(originalURL, "ai4edatasetspublicassets.blob.core.windows.net") {
			log.Printf("Skipping token signing for public assets URL: %s", originalURL)
			continue
		}

		// Add the token to the URL
		signedURL := originalURL + "?" + token

		// Replace in content, being careful with various JSON formats
		modifiedContent = strings.Replace(
			modifiedContent,
			fmt.Sprintf("\"href\":\"%s\"", originalURL),
			fmt.Sprintf("\"href\":\"%s\"", signedURL),
			-1,
		)

		modifiedContent = strings.Replace(
			modifiedContent,
			fmt.Sprintf("\"url\":\"%s\"", originalURL),
			fmt.Sprintf("\"url\":\"%s\"", signedURL),
			-1,
		)

		signedCount++
	}

	log.Printf("Signed %d blob URLs", signedCount)
	return modifiedContent
}
