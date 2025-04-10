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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
)

const (
	proxyPort      = 8080
	targetBaseURL  = "https://planetarycomputer.microsoft.com"
	tokenEndpoint  = "https://planetarycomputer.microsoft.com/api/sas/v1/token"
	defaultTimeout = 30 * time.Second
	tokenCacheFile = "token_cache.json"
	savePeriod     = 5 * time.Minute // How often to save tokens to disk
)

// TokenResponse represents the response from token API
type TokenResponse struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"msft:expiry"`
}

// Cache for tokens to reduce API calls
type TokenCache struct {
	mu           sync.RWMutex
	tokens       map[string]TokenResponse
	lastSaveTime time.Time
	dirty        bool // Indicates if there are unsaved changes
}

// Global token cache
var tokenCache = TokenCache{
	tokens:       make(map[string]TokenResponse),
	lastSaveTime: time.Now(),
}

var collectionRegex = regexp.MustCompile(`/collections/([^/]+)`)

func main() {
	log.Printf("Starting direct proxy on port %d", proxyPort)
	log.Printf("Target API: %s", targetBaseURL)
	log.Printf("Token cache file: %s", tokenCacheFile)
	
	// Load saved tokens from disk
	loadTokenCache()
	
	// Start background saving of token cache
	go startTokenCacheSaver()
	
	// Setup graceful shutdown to save tokens
	http.HandleFunc("/", handleProxyRequest)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", proxyPort),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

// loadTokenCache loads tokens from disk at startup
func loadTokenCache() {
	file, err := os.Open(tokenCacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("No token cache file found at %s, will create when tokens are fetched", tokenCacheFile)
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

	// Filter out expired tokens
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

// saveTokenCache saves tokens to disk
func saveTokenCache() error {
	tokenCache.mu.RLock()
	if !tokenCache.dirty {
		tokenCache.mu.RUnlock()
		return nil // Skip saving if no changes
	}
	
	// Create a copy of tokens to avoid holding the lock during I/O
	tokenCopy := make(map[string]TokenResponse)
	for k, v := range tokenCache.tokens {
		tokenCopy[k] = v
	}
	tokenCache.mu.RUnlock()

	// Create directory if it doesn't exist
	dir := filepath.Dir(tokenCacheFile)
	if dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory for token cache: %w", err)
		}
	}

	// Use a temporary file and atomic rename to avoid corruption
	tempFile := tokenCacheFile + ".tmp"
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

	// Atomic rename
	if err := os.Rename(tempFile, tokenCacheFile); err != nil {
		return fmt.Errorf("renaming token cache file: %w", err)
	}

	// Mark as saved
	tokenCache.mu.Lock()
	tokenCache.dirty = false
	tokenCache.lastSaveTime = time.Now()
	tokenCache.mu.Unlock()

	log.Printf("Saved %d tokens to cache file", len(tokenCopy))
	return nil
}

// startTokenCacheSaver runs a background goroutine to periodically save tokens
func startTokenCacheSaver() {
	ticker := time.NewTicker(savePeriod)
	defer ticker.Stop()

	for {
		<-ticker.C
		if err := saveTokenCache(); err != nil {
			log.Printf("Error saving token cache: %v", err)
		}
	}
}

func extractCollection(path string) string {
	matches := collectionRegex.FindStringSubmatch(path)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)

	// Extract collection from path - useful for token fetching later
	collection := extractCollection(r.URL.Path)
	if collection != "" {
		log.Printf("Detected collection: %s", collection)
	}

	// Create the target URL
	targetURL := fmt.Sprintf("%s%s", targetBaseURL, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), defaultTimeout)
	defer cancel()

	// Create the request to the target API
	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers from the original request
	for name, values := range r.Header {
		// Skip host header which is set automatically
		if strings.ToLower(name) != "host" {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
	}

	// Set the User-Agent
	req.Header.Set("User-Agent", "DirectProxy/1.0")

	// Create a client with reasonable timeouts
	client := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			IdleConnTimeout:     90 * time.Second,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			DisableCompression:  false, // Allow compression
		},
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error forwarding request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Check if it's a STAC API response that needs transformation
	if isSTACResponse(resp) && strings.Contains(r.URL.Path, "/api/stac/v1") {
		transformedResp, err := transformSTACResponse(resp, collection)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error transforming response: %v", err), http.StatusInternalServerError)
			return
		}
		resp = transformedResp
	}

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
		return
	}

	log.Printf("Successfully proxied request: %s %s -> %d", r.Method, r.URL.Path, resp.StatusCode)
}

func isSTACResponse(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(contentType), "json") &&
		resp.StatusCode == http.StatusOK &&
		resp.ContentLength != 0
}

func transformSTACResponse(resp *http.Response, requestedCollection string) (*http.Response, error) {
	log.Printf("Transforming STAC response with Content-Type: %s, Content-Encoding: %s",
		resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding"))

	// Read and decompress response body
	var bodyBytes []byte
	var err error
	contentEncoding := resp.Header.Get("Content-Encoding")

	switch contentEncoding {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		defer reader.Close()
		bodyBytes, err = io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("reading gzipped body: %w", err)
		}

	case "br":
		reader := brotli.NewReader(resp.Body)
		bodyBytes, err = io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("reading brotli body: %w", err)
		}

	default:
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
	}

	// Process the response body
	bodyStr := string(bodyBytes)
	
	// Determine which collection to use for token fetching
	collection := ""
	
	// First priority: use the collection from the request path if available
	if requestedCollection != "" {
		collection = requestedCollection
	} else {
		// Second priority: try to extract collection from the response body
		var stacDoc map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &stacDoc); err == nil {
			// Try different fields that might contain collection info
			if collID, ok := stacDoc["collection"].(string); ok && collID != "" {
				collection = collID
			} else if collID, ok := stacDoc["id"].(string); ok && collID != "" {
				collection = collID
			}
		}
		
		// Third priority: try to extract from URLs in the response
		if collection == "" {
			matches := collectionRegex.FindStringSubmatch(bodyStr)
			if len(matches) > 1 && matches[1] != "" {
				collection = matches[1]
			}
		}
		
		// Fourth priority: use the default collection
		if collection == "" {
			collection = "sentinel-2-l2a"
		}
	}
	
	log.Printf("Using collection '%s' for token fetching", collection)
	
	// Get token for the identified collection
	token, err := getTokenCached(collection)
	if err != nil {
		log.Printf("Error getting token: %v", err)
		// Continue without signing URLs if token fetch fails
	} else {
		log.Printf("Got token for collection %s", collection)
	}

	// Replace API URLs to point to our proxy
	originalAPIBase := "https://planetarycomputer.microsoft.com"
	proxyAPIBase := fmt.Sprintf("http://localhost:%d", proxyPort)
	bodyStr = strings.ReplaceAll(bodyStr, originalAPIBase, proxyAPIBase)

	// Find and sign blob URLs if we have a token
	if token != "" {
		bodyStr = signBlobURLs(bodyStr, token)
	}

	// Create new response
	newResp := *resp // Copy the original response
	
	// For uncompressed responses, return the modified body as is
	if contentEncoding == "" {
		newResp.Body = io.NopCloser(strings.NewReader(bodyStr))
		newResp.ContentLength = int64(len(bodyStr))
		newResp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyStr)))
		return &newResp, nil
	}

	// For compressed responses, recompress with the same algorithm
	var contentBuffer bytes.Buffer

	switch contentEncoding {
	case "gzip":
		gzipWriter := gzip.NewWriter(&contentBuffer)
		_, err := gzipWriter.Write([]byte(bodyStr))
		if err != nil {
			return nil, fmt.Errorf("compressing with gzip: %w", err)
		}
		if err := gzipWriter.Close(); err != nil {
			return nil, fmt.Errorf("closing gzip writer: %w", err)
		}

	case "br":
		brWriter := brotli.NewWriter(&contentBuffer)
		_, err := brWriter.Write([]byte(bodyStr))
		if err != nil {
			return nil, fmt.Errorf("compressing with brotli: %w", err)
		}
		if err := brWriter.Close(); err != nil {
			return nil, fmt.Errorf("closing brotli writer: %w", err)
		}
	}

	newResp.Body = io.NopCloser(bytes.NewReader(contentBuffer.Bytes()))
	newResp.ContentLength = int64(contentBuffer.Len())
	newResp.Header.Set("Content-Length", fmt.Sprintf("%d", contentBuffer.Len()))

	return &newResp, nil
}

func signBlobURLs(content, token string) string {
	// Find blob URLs using simple string search
	var blobURLs []string
	startIdx := 0
	for {
		startLoc := strings.Index(content[startIdx:], "https://")
		if startLoc == -1 {
			break
		}
		startLoc += startIdx

		// Find the end of the URL (quote or space)
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

	// Replace blob URLs with signed versions in the content
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

// getTokenCached retrieves a token from cache or fetches a new one if needed
func getTokenCached(collection string) (string, error) {
	// Check cache first
	tokenCache.mu.RLock()
	cachedToken, exists := tokenCache.tokens[collection]
	tokenCache.mu.RUnlock()
	
	// If token exists and is not expired, use it
	if exists && time.Now().Before(cachedToken.Expiry) {
		log.Printf("Using cached token for %s (expires in %v)", 
			collection, cachedToken.Expiry.Sub(time.Now()).Round(time.Second))
		return cachedToken.Token, nil
	}
	
	// Otherwise fetch a new token
	tokenResp, err := fetchToken(collection)
	if err != nil {
		return "", err
	}
	
	// Cache the new token
	tokenCache.mu.Lock()
	tokenCache.tokens[collection] = tokenResp
	tokenCache.dirty = true // Mark that we have unsaved changes
	tokenCache.mu.Unlock()
	
	// Save to disk immediately after getting a new token
	go func() {
		if err := saveTokenCache(); err != nil {
			log.Printf("Error saving token cache: %v", err)
		} else {
			log.Printf("Saved token cache with %d entries to %s", len(tokenCache.tokens), tokenCacheFile)
		}
	}()
	
	return tokenResp.Token, nil
}

func fetchToken(collection string) (TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/%s", tokenEndpoint, collection)
	log.Printf("Fetching fresh token from %s", tokenURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set("User-Agent", "DirectProxy/1.0")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("sending token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
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

	// Set a default expiry if none provided
	if tokenResp.Expiry.IsZero() {
		tokenResp.Expiry = time.Now().Add(1 * time.Hour)
		log.Printf("No expiry in token response, using default 1 hour expiry")
	}

	log.Printf("Token obtained for %s (expires: %v)", collection, tokenResp.Expiry.Format(time.RFC3339))
	return tokenResp, nil
}
