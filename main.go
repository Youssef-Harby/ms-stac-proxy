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
	defaultTimeout        = 30 * time.Second
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
	blobURLRegex        = regexp.MustCompile(`https://\w+\.blob\.core\.windows\.net/[\w-]+/([^/]+)/[^?#]+(?:\.[^?#.]+)?`)

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

	log.Printf("Starting STAC Proxy on port %d", config.ProxyPort)
	log.Printf("Target API: %s", config.TargetBaseURL)
	log.Printf("Token cache file: %s", config.TokenCacheFile)

	loadTokenCache()

	cacheSaverDone := make(chan struct{})
	go startTokenCacheSaver(cacheSaverDone)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	mux := http.NewServeMux()
	mux.HandleFunc("/", corsMiddleware(handleProxyRequest))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.ProxyPort),
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

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
		transformedResp, err := transformSTACResponse(resp, collection)
		if err != nil {
			http.Error(w, "Error transforming response", statusInternalServerError)
			log.Printf("Error transforming response: %v", err)
			return
		}
		resp = transformedResp
	}

	// Copy response headers to client response
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Ensure CORS headers are properly set on the response
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-API-Key, Cache-Control, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type, Cache-Control")
	}

	// Write status code and body
	w.WriteHeader(resp.StatusCode)
	
	// Debug the response content
	bodyBytes, _ := io.ReadAll(resp.Body)
	if len(bodyBytes) == 0 {
		log.Printf("Warning: Empty response body after transformation")
	} else {
		log.Printf("Response body length: %d bytes", len(bodyBytes))
	}
	
	// Write the body to the response
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

func transformSTACResponse(resp *http.Response, collectionID string) (*http.Response, error) {
	contentType := resp.Header.Get(headerContentType)
	contentEncoding := resp.Header.Get(headerContentEncoding)

	log.Printf("Transforming STAC response with Content-Type: %s, Content-Encoding: %s", contentType, contentEncoding)

	// Clone the original headers first to preserve them
	preservedHeaders := resp.Header.Clone()

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

	// Get collection ID for token if none provided
	if collectionID == "" {
		collectionID = findCollectionInResponse(bodyStr)
		if collectionID != "" {
			log.Printf("Using collection '%s' for token fetching", collectionID)
		}
	}

	// Sign blob URLs in the response if we have a collection ID
	if collectionID != "" {
		token, err := getTokenCached(collectionID)
		if err != nil {
			log.Printf("Error getting token: %v", err)
		} else {
			bodyStr = signBlobURLs(bodyStr, token)
		}
	}

	// Replace API URLs
	bodyStr = strings.ReplaceAll(bodyStr, config.TargetBaseURL, fmt.Sprintf("http://localhost:%d", config.ProxyPort))

	// Create a new response with the modified body
	newResp := *resp
	
	// Create new http.Response with original headers
	newResp.Header = preservedHeaders.Clone()
	
	// Always return uncompressed content for simplicity
	newResp.Body = io.NopCloser(strings.NewReader(bodyStr))
	newResp.ContentLength = int64(len(bodyStr))
	newResp.Header.Set(headerContentLength, fmt.Sprintf("%d", len(bodyStr)))
	
	// Remove content encoding header since we're returning uncompressed content
	newResp.Header.Del(headerContentEncoding)

	return &newResp, nil
}

func signBlobURLs(content, token string) string {
	blobURLs := []string{}
	startIdx := 0
	for {
		startLoc := strings.Index(content[startIdx:], "https://")
		if startLoc == -1 {
			break
		}
		startLoc += startIdx

		endLoc := -1
		for i := startLoc; i < len(content); i++ {
			if content[i] == '"' || content[i] == ' ' || content[i] == '\n' {
				endLoc = i
				break
			}
		}
		if endLoc == -1 {
			break
		}

		url := content[startLoc:endLoc]
		if strings.Contains(url, ".blob.core.windows.net") && !strings.Contains(url, "?") {
			blobURLs = append(blobURLs, url)
		}
		startIdx = endLoc
	}

	modifiedContent := content
	signedCount := 0
	for _, blobURL := range blobURLs {
		signedURL := blobURL + "?" + token
		modifiedContent = strings.Replace(
			modifiedContent,
			fmt.Sprintf("\"href\":\"%s\"", blobURL),
			fmt.Sprintf("\"href\":\"%s\"", signedURL),
			-1,
		)
		signedCount++
	}

	log.Printf("Signed %d blob URLs", signedCount)
	return modifiedContent
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

	if resp.StatusCode != statusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return TokenResponse{}, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return TokenResponse{}, fmt.Errorf("decoding token response: %w", err)
	}

	if tokenResp.Token == "" {
		return TokenResponse{}, fmt.Errorf("received empty token")
	}

	if tokenResp.Expiry.IsZero() {
		tokenResp.Expiry = time.Now().Add(1 * time.Hour)
		log.Printf("No expiry in token response, using default 1 hour expiry")
	}

	log.Printf("Token obtained for %s (expires: %v)", collection, tokenResp.Expiry.Format(time.RFC3339))
	return tokenResp, nil
}

func findCollectionInResponse(content string) string {
	var stacDoc map[string]interface{}
	if err := json.Unmarshal([]byte(content), &stacDoc); err == nil {
		if collID, ok := stacDoc["collection"].(string); ok && collID != "" {
			return collID
		}

		if collID, ok := stacDoc["id"].(string); ok && collID != "" {
			return collID
		}

		if links, ok := stacDoc["links"].([]interface{}); ok {
			for _, link := range links {
				if linkMap, ok := link.(map[string]interface{}); ok {
					if rel, ok := linkMap["rel"].(string); ok && rel == "collection" {
						if href, ok := linkMap["href"].(string); ok {
							matches := collectionPathRegex.FindStringSubmatch(href)
							if len(matches) > 1 {
								return matches[1]
							}
						}
					}
				}
			}
		}
	}

	matches := blobURLRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}

	matches = collectionPathRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		coll := matches[1]
		if !strings.Contains(coll, "{") && !strings.Contains(coll, "}") &&
		   !strings.Contains(coll, "\"") && !strings.Contains(coll, "'") {
			return coll
		}
	}

	return "sentinel-2-l2a"
}

func extractCollection(path string) string {
	matches := collectionPathRegex.FindStringSubmatch(path)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-API-Key, Cache-Control, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type, Cache-Control")
		
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
