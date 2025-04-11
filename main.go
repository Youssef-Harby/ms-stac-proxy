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
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
)

// Constants
const (
	defaultProxyPort      = 8080
	defaultTargetBaseURL  = "https://planetarycomputer.microsoft.com"
	defaultTokenEndpoint  = "https://planetarycomputer.microsoft.com/api/sas/v1/token"
	defaultTokenCacheFile = "token_cache.json"
	defaultTimeout        = 60 * time.Second
	defaultSavePeriod     = 5 * time.Minute
	defaultRetryAttempts  = 3
	defaultRetryDelay     = 500 * time.Millisecond
	tokenExpiryBuffer     = 60
	directSignEndpoint    = "%s/api/sas/v1/sign?href=%s"
)

// HTTP header constants
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

// HTTP status constants
const (
	statusOK                  = http.StatusOK
	statusBadRequest          = http.StatusBadRequest
	statusInternalServerError = http.StatusInternalServerError
	statusBadGateway          = http.StatusBadGateway
)

// Config holds the application configuration
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

// TokenResponse represents the token data returned from the API
type TokenResponse struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"msft:expiry"`
}

// DirectSignToken represents a token extracted from a directly signed URL
type DirectSignToken struct {
	Token  string
	Expiry time.Time
}

// TokenCache manages token storage and retrieval
type TokenCache struct {
	mu           sync.RWMutex
	tokens       map[string]TokenResponse
	directTokens map[string]DirectSignToken // Cache for tokens from direct signing
	lastSaveTime time.Time
	dirty        bool
}

// Application encapsulates global state
type Application struct {
	config              Config
	tokenCache          TokenCache
	httpClient          *http.Client
	collectionRegex     *regexp.Regexp
	blobURLRegex        *regexp.Regexp
	tokenParamsRegex    *regexp.Regexp
	shutdownCh          chan struct{}
	cacheSaverDone      chan struct{}
	directSignCollections map[string]bool // Collections that need direct signing
}

// NewApplication creates and initializes a new application
func NewApplication() *Application {
	app := &Application{
		tokenCache: TokenCache{
			tokens:       make(map[string]TokenResponse),
			directTokens: make(map[string]DirectSignToken),
			lastSaveTime: time.Now(),
		},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 100,
				MaxConnsPerHost:     1000,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false, // Allow compression
				ForceAttemptHTTP2:   true,  // Attempt HTTP/2
			},
		},
		collectionRegex:     regexp.MustCompile(`/collections/([^/?#]+)`),
		blobURLRegex:        regexp.MustCompile(`https://([^\.]+)\.blob\.core\.windows\.net/([^/]+)/([^"?\s]+)`),
		tokenParamsRegex:    regexp.MustCompile(`[?&](st|se|sp|sv|sr|skoid|sktid|skt|ske|sks|skv|sig)=`),
		shutdownCh:          make(chan struct{}),
		cacheSaverDone:      make(chan struct{}),
		directSignCollections: map[string]bool{
			"gnatsgo": true,
			"soils": true,
			"gnatsgo-rasters": true,
			"noaa-cdr-ocean-heat-content": true,
			"cop-dem-glo-90": true,
			"cop-dem-glo-30": true,
			// Add other collections that need direct signing here
		},
	}

	// Load configuration
	app.config = app.loadConfig()
	app.httpClient.Timeout = app.config.Timeout

	return app
}

// loadConfig loads configuration from environment variables and command line flags
func (app *Application) loadConfig() Config {
	// Parse command line flags
	var portFlag int
	flag.IntVar(&portFlag, "p", 0, "Set the proxy port (overrides PROXY_PORT environment variable)")
	flag.Parse()

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

	// Command line flags take precedence over environment variables
	if portFlag > 0 {
		cfg.ProxyPort = portFlag
	} else if port := os.Getenv("PROXY_PORT"); port != "" {
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

	return cfg
}

func main() {
	app := NewApplication()
	app.Run()
}

// Run starts the application
func (app *Application) Run() {
	stacAPIURL := fmt.Sprintf("http://localhost:%d/api/stac/v1", app.config.ProxyPort)
	targetStacAPI := fmt.Sprintf("%s/api/stac/v1", app.config.TargetBaseURL)

	log.Printf("##############################################################")
	log.Printf("# Microsoft STAC Proxy Service Started                       #")
	log.Printf("# STAC API URL: %-43s #", stacAPIURL)
	log.Printf("# GitHub Repository: %-38s #", "https://github.com/Youssef-Harby/ms-stac-proxy")
	log.Printf("# Target API: %-45s #", targetStacAPI)
	log.Printf("# Token cache file: %-39s #", app.config.TokenCacheFile)
	log.Printf("##############################################################")

	app.loadTokenCache()

	go app.startTokenCacheSaver()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.corsMiddleware(app.handleProxyRequest))

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", app.config.ProxyPort),
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Server bound to all interfaces (0.0.0.0) on port %d", app.config.ProxyPort)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %v", err)
		}
	}()

	<-sigChan
	log.Println("Shutdown signal received, shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	close(app.shutdownCh)
	close(app.cacheSaverDone)

	if err := app.saveTokenCache(); err != nil {
		log.Printf("Error saving token cache during shutdown: %v", err)
	}

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}

// startTokenCacheSaver periodically saves the token cache to disk
func (app *Application) startTokenCacheSaver() {
	ticker := time.NewTicker(app.config.SavePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := app.saveTokenCache(); err != nil {
				log.Printf("Error saving token cache: %v", err)
			}
		case <-app.cacheSaverDone:
			log.Println("Token cache saver stopped")
			return
		case <-app.shutdownCh:
			return
		}
	}
}

// handleProxyRequest processes incoming HTTP requests
func (app *Application) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)

	collection := app.extractCollection(r.URL.Path)
	if collection != "" {
		log.Printf("Detected collection: %s", collection)
	}

	targetURL := fmt.Sprintf("%s%s", app.config.TargetBaseURL, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL = fmt.Sprintf("%s?%s", targetURL, r.URL.RawQuery)
	}

	ctx, cancel := context.WithTimeout(r.Context(), app.config.Timeout)
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

	resp, err := app.httpClient.Do(proxyReq)
	if err != nil {
		http.Error(w, "Error forwarding request", statusBadGateway)
		log.Printf("Error forwarding request: %v", err)
		return
	}
	defer resp.Body.Close()

	if app.isSTACResponse(resp) {
		transformedResp, err := app.transformSTACResponse(resp, collection, r.Host)
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

// isSTACResponse checks if the response is a STAC API JSON response
func (app *Application) isSTACResponse(resp *http.Response) bool {
	contentType := resp.Header.Get(headerContentType)
	return strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/geo+json") ||
		strings.Contains(contentType, "application/stac") ||
		strings.Contains(contentType, "application/ld+json")
}

// transformSTACResponse transforms the STAC API response
func (app *Application) transformSTACResponse(resp *http.Response, collectionID string, hostHeader string) (*http.Response, error) {
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
		collectionID = app.findCollectionInResponse(bodyStr)
		if collectionID != "" {
			log.Printf("Using collection '%s' for token fetching", collectionID)
		}
	}

	// First try signing as a STAC structure (Item or ItemCollection)
	if strings.Contains(contentType, "application/json") {
		signedContent, err := app.DetectAndSignSTACItem(bodyStr, collectionID)
		if err != nil {
			log.Printf("Error during STAC structure signing: %v", err)
		} else if signedContent != bodyStr {
			bodyStr = signedContent
		} else {
			// If not a STAC structure or no changes, fall back to generic blob URL signing
			if strings.Contains(bodyStr, ".blob.core.windows.net") {
				token, err := app.getTokenCached(collectionID)
				if err != nil {
					log.Printf("Error getting token for collection %s: %v", collectionID, err)
				} else {
					bodyStr = app.signBlobURLs(bodyStr, token, collectionID)
				}
			}
		}
	} else {
		// Not JSON, use generic blob URL signing
		if strings.Contains(bodyStr, ".blob.core.windows.net") {
			token, err := app.getTokenCached(collectionID)
			if err != nil {
				log.Printf("Error getting token for collection %s: %v", collectionID, err)
			} else {
				bodyStr = app.signBlobURLs(bodyStr, token, collectionID)
			}
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
	bodyStr = strings.ReplaceAll(bodyStr, app.config.TargetBaseURL, proxyBaseURL)

	newResp := *resp
	newResp.Header = resp.Header.Clone()
	newResp.Body = io.NopCloser(strings.NewReader(bodyStr))
	newResp.ContentLength = int64(len(bodyStr))
	newResp.Header.Set(headerContentLength, fmt.Sprintf("%d", len(bodyStr)))
	newResp.Header.Del(headerContentEncoding)

	return &newResp, nil
}

// findCollectionInResponse extracts collection ID from a STAC response
func (app *Application) findCollectionInResponse(content string) string {
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
	matches := app.collectionRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}

	// If we still don't have a collection ID, use a default
	// This is a simple failsafe - the blob URLs will still get signed regardless
	return "default-collection"
}

// extractCollection extracts collection ID from a request path
func (app *Application) extractCollection(path string) string {
	collectionMatch := app.collectionRegex.FindStringSubmatch(path)
	if len(collectionMatch) > 1 {
		return collectionMatch[1]
	}
	return ""
}

// getTokenCached gets a token for a collection, using cache if possible
func (app *Application) getTokenCached(collection string) (string, error) {
	app.tokenCache.mu.RLock()
	cachedToken, exists := app.tokenCache.tokens[collection]
	app.tokenCache.mu.RUnlock()

	now := time.Now()
	// Check if token exists, is not expired, and has more than buffer time left
	if exists && now.Add(tokenExpiryBuffer*time.Second).Before(cachedToken.Expiry) {
		log.Printf("Using cached token for %s (expires in %v)",
			collection, cachedToken.Expiry.Sub(now).Round(time.Second))
		return cachedToken.Token, nil
	}

	var tokenResp TokenResponse
	var err error

	for attempt := 0; attempt < app.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * app.config.RetryDelay
			log.Printf("Retrying token fetch for %s (attempt %d/%d) after %v",
				collection, attempt+1, app.config.RetryAttempts, backoff)
			select {
			case <-time.After(backoff):
				// Continue with retry
			case <-app.shutdownCh:
				return "", fmt.Errorf("shutdown in progress")
			}
		}

		tokenResp, err = app.fetchToken(collection)
		if err == nil {
			break
		}

		if !app.isRetryableError(err) {
			break
		}
	}

	if err != nil {
		return "", err
	}

	app.tokenCache.mu.Lock()
	app.tokenCache.tokens[collection] = tokenResp
	app.tokenCache.dirty = true
	app.tokenCache.mu.Unlock()

	go func() {
		if err := app.saveTokenCache(); err != nil {
			log.Printf("Error saving token cache: %v", err)
		} else {
			log.Printf("Saved token cache with %d entries to %s", len(app.tokenCache.tokens), app.config.TokenCacheFile)
		}
	}()

	return tokenResp.Token, nil
}

// isRetryableError determines if an error should trigger a retry
func (app *Application) isRetryableError(err error) bool {
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

// fetchToken fetches a fresh token from the token endpoint
func (app *Application) fetchToken(collection string) (TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/%s", app.config.TokenEndpoint, collection)
	log.Printf("Fetching fresh token from %s", tokenURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set(headerUserAgent, "STACProxy/1.0")
	req.Header.Set(headerAccept, "application/json")

	resp, err := app.httpClient.Do(req)
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
		// If it's not in RFC3339 format, try other formats commonly used for SAS tokens
		parsedExpiry, err = time.Parse("2006-01-02T15:04:05Z", tokenResp.ExpiryString)
		if err != nil {
			return TokenResponse{}, fmt.Errorf("parsing token expiry time: %w", err)
		}
	}

	log.Printf("Token obtained for %s (expires: %s)", collection, parsedExpiry.Format(time.RFC3339))

	return TokenResponse{
		Token:  tokenResp.Token,
		Expiry: parsedExpiry,
	}, nil
}

// corsMiddleware adds CORS headers to responses
func (app *Application) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
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

// loadTokenCache loads the token cache from disk
func (app *Application) loadTokenCache() {
	app.tokenCache.mu.Lock()
	defer app.tokenCache.mu.Unlock()

	file, err := os.Open(app.config.TokenCacheFile)
	if os.IsNotExist(err) {
		log.Printf("Token cache file does not exist, starting with empty cache")
		return
	} else if err != nil {
		log.Printf("Error opening token cache file: %v", err)
		return
	}
	defer file.Close()

	// Define structure for deserialization
	type savedToken struct {
		Token  string    `json:"token"`
		Expiry time.Time `json:"expiry"`
	}

	type tokenCacheFile struct {
		Tokens       map[string]savedToken `json:"tokens"`
		DirectTokens map[string]savedToken `json:"direct_tokens"`
		SaveTime     time.Time             `json:"save_time"`
	}

	var saveData tokenCacheFile
	if err := json.NewDecoder(file).Decode(&saveData); err != nil {
		log.Printf("Error decoding token cache file: %v", err)
		return
	}

	// Process regular tokens
	now := time.Now()
	validCount := 0
	expiredCount := 0

	for collection, token := range saveData.Tokens {
		if now.Before(token.Expiry) {
			app.tokenCache.tokens[collection] = TokenResponse{
				Token:  token.Token,
				Expiry: token.Expiry,
			}
			validCount++
		} else {
			expiredCount++
		}
	}
	
	// Process direct tokens
	directValidCount := 0
	directExpiredCount := 0
	
	for collection, token := range saveData.DirectTokens {
		if now.Before(token.Expiry) {
			app.tokenCache.directTokens[collection] = DirectSignToken{
				Token:  token.Token,
				Expiry: token.Expiry,
			}
			directValidCount++
		} else {
			directExpiredCount++
		}
	}

	log.Printf("Loaded %d valid tokens from cache (discarded %d expired)", validCount+directValidCount, expiredCount+directExpiredCount)
}

// saveTokenCache saves the token cache to disk
func (app *Application) saveTokenCache() error {
	app.tokenCache.mu.Lock()
	defer app.tokenCache.mu.Unlock()

	if !app.tokenCache.dirty {
		return nil
	}

	// Filter out expired tokens before saving
	now := time.Now()
	validTokens := make(map[string]TokenResponse)
	for collection, token := range app.tokenCache.tokens {
		if now.Before(token.Expiry) {
			validTokens[collection] = token
		}
	}
	
	// Also filter expired direct tokens
	validDirectTokens := make(map[string]DirectSignToken)
	for collection, token := range app.tokenCache.directTokens {
		if now.Before(token.Expiry) {
			validDirectTokens[collection] = token
		}
	}

	// Create a serializable structure for tokens
	type savedToken struct {
		Token  string    `json:"token"`
		Expiry time.Time `json:"expiry"`
	}

	type tokenCacheFile struct {
		Tokens       map[string]savedToken `json:"tokens"`
		DirectTokens map[string]savedToken `json:"direct_tokens"`
		SaveTime     time.Time             `json:"save_time"`
	}

	saveData := tokenCacheFile{
		Tokens:       make(map[string]savedToken),
		DirectTokens: make(map[string]savedToken),
		SaveTime:     time.Now(),
	}

	for collection, token := range validTokens {
		saveData.Tokens[collection] = savedToken{
			Token:  token.Token,
			Expiry: token.Expiry,
		}
	}
	
	for collection, token := range validDirectTokens {
		saveData.DirectTokens[collection] = savedToken{
			Token:  token.Token,
			Expiry: token.Expiry,
		}
	}

	fileData, err := json.MarshalIndent(saveData, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling token cache: %w", err)
	}

	file, err := os.OpenFile(app.config.TokenCacheFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening token cache file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(fileData); err != nil {
		return fmt.Errorf("writing token cache file: %w", err)
	}

	app.tokenCache.lastSaveTime = time.Now()
	app.tokenCache.dirty = false

	log.Printf("Saved %d tokens to disk", len(validTokens) + len(validDirectTokens))
	return nil
}

// extractTokenFromSignedURL extracts the SAS token from a signed URL
func (app *Application) extractTokenFromSignedURL(signedURL string) (string, time.Time, error) {
	// Parse the URL to extract query parameters
	parsedURL, err := url.Parse(signedURL)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parsing signed URL: %w", err)
	}
	
	// Get the query parameters
	query := parsedURL.Query()
	
	// Check if this URL has the required SAS token parameters
	hasSignature := query.Get("sig") != ""
	hasStartTime := query.Get("st") != ""
	hasEndTime := query.Get("se") != ""
	
	if !hasSignature || !hasStartTime || !hasEndTime {
		return "", time.Time{}, fmt.Errorf("URL does not contain required SAS token parameters")
	}
	
	// Extract expiry time
	expiryStr := query.Get("se")
	expiry, err := time.Parse(time.RFC3339, expiryStr)
	if err != nil {
		// If it's not in RFC3339 format, try other formats commonly used for SAS tokens
		expiry, err = time.Parse("2006-01-02T15:04:05Z", expiryStr)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("parsing token expiry time: %w", err)
		}
	}
	
	// Remove the path and hostname part to get just the query string
	tokenPart := parsedURL.RawQuery
	
	return tokenPart, expiry, nil
}

// getDirectSignTokenCached gets or creates a direct-sign token for a specific collection
func (app *Application) getDirectSignTokenCached(collection string, assetURL string) (string, error) {
	if collection == "" {
		collection = "default-collection"
	}

	// Check if we have a cached direct token for this collection
	app.tokenCache.mu.RLock()
	cachedToken, exists := app.tokenCache.directTokens[collection]
	app.tokenCache.mu.RUnlock()

	now := time.Now()
	
	// If we have a valid cached token that's not about to expire, use it
	if exists && now.Add(tokenExpiryBuffer*time.Second).Before(cachedToken.Expiry) {
		log.Printf("Using cached direct-sign token for %s (expires in %v)", 
			collection, cachedToken.Expiry.Sub(now).Round(time.Second))
		return cachedToken.Token, nil
	}
	
	// Otherwise, we need to fetch a new token by directly signing one asset
	log.Printf("Directly signing one asset to extract token for collection: %s", collection)
	
	// Directly sign one asset URL
	signedURL, err := app.SignDirectURL(assetURL)
	if err != nil {
		return "", fmt.Errorf("direct signing for token extraction: %w", err)
	}
	
	// Extract the token from the signed URL
	token, expiry, err := app.extractTokenFromSignedURL(signedURL)
	if err != nil {
		return "", fmt.Errorf("extracting token from signed URL: %w", err)
	}
	
	// Cache the token
	app.tokenCache.mu.Lock()
	app.tokenCache.directTokens[collection] = DirectSignToken{
		Token:  token,
		Expiry: expiry,
	}
	app.tokenCache.dirty = true
	app.tokenCache.mu.Unlock()
	
	log.Printf("Cached new direct-sign token for %s (expires: %s)", 
		collection, expiry.Format(time.RFC3339))
	
	return token, nil
}

// signBlobURLs adds SAS tokens to Azure blob URLs
func (app *Application) signBlobURLs(content, token string, collection string) string {
	// Find all matches in the content
	matches := app.blobURLRegex.FindAllString(content, -1)
	if len(matches) == 0 {
		return content
	}

	modifiedContent := content
	signedCount := 0
	needsDirectSigning := app.directSignCollections[collection]
	
	var directSignToken string
	foundFirstAsset := false

	for _, originalURL := range matches {
		// Skip URLs that already have a signature (containing SAS token params)
		if app.isURLSigned(originalURL) {
			log.Printf("Skipping already signed URL: %s", originalURL)
			continue
		}

		// Skip specific storage accounts that don't need signing or have different auth
		if strings.Contains(originalURL, "ai4edatasetspublicassets.blob.core.windows.net") {
			log.Printf("Skipping token signing for public assets URL: %s", originalURL)
			continue
		}

		var signedURL string
		if needsDirectSigning {
			// For directly signed collections:
			if !foundFirstAsset {
				// For the first asset, get or create a direct token
				foundFirstAsset = true
				var err error
				directSignToken, err = app.getDirectSignTokenCached(collection, originalURL)
				if err != nil {
					log.Printf("Error getting direct token, falling back to collection token: %v", err)
					signedURL = originalURL + "?" + token
				} else {
					// Apply the token
					signedURL = originalURL + "?" + directSignToken
				}
			} else {
				// For subsequent assets, reuse the same direct token
				if directSignToken != "" {
					signedURL = originalURL + "?" + directSignToken
				} else {
					// If we failed to get a direct token earlier, use collection token
					signedURL = originalURL + "?" + token
				}
			}
		} else {
			// Use collection token (the original approach)
			signedURL = originalURL + "?" + token
		}

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

// isURLSigned checks if a URL already has SAS token parameters
func (app *Application) isURLSigned(url string) bool {
	return app.tokenParamsRegex.MatchString(url)
}

// SignDirectURL signs a specific URL directly using the direct signing endpoint
// This is useful for signing individual assets without needing a collection token
func (app *Application) SignDirectURL(blobURL string) (string, error) {
	// Skip if URL is already signed
	if app.isURLSigned(blobURL) {
		return blobURL, nil
	}
	
	// Skip specific storage accounts that don't need signing
	if strings.Contains(blobURL, "ai4edatasetspublicassets.blob.core.windows.net") {
		return blobURL, nil
	}
	
	// Construct direct signing URL
	signURL := fmt.Sprintf(directSignEndpoint, app.config.TargetBaseURL, blobURL)
	
	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating direct signing request: %w", err)
	}
	
	req.Header.Set(headerUserAgent, "STACProxy/1.0")
	req.Header.Set(headerAccept, "application/json")
	
	// Send request
	resp, err := app.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending direct signing request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status code from signing endpoint: %d, body: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var signedLink struct {
		HREF   string    `json:"href"`
		Expiry time.Time `json:"msft:expiry"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&signedLink); err != nil {
		return "", fmt.Errorf("decoding direct signing response: %w", err)
	}
	
	log.Printf("Directly signed URL (expires: %s)", signedLink.Expiry.Format(time.RFC3339))
	return signedLink.HREF, nil
}

// DetectAndSignSTACItem examines a JSON payload to see if it's a STAC Item
// and if so, signs all assets within it
func (app *Application) DetectAndSignSTACItem(content string, collection string) (string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		// Not valid JSON, return as is
		return content, nil
	}
	
	// Check if this is a STAC Item
	if t, ok := data["type"].(string); ok && t == "Feature" {
		if _, hasProps := data["properties"]; hasProps {
			if assets, hasAssets := data["assets"].(map[string]interface{}); hasAssets {
				// This looks like a STAC Item
				
				// Check if this collection needs direct signing
				needsDirectSigning := app.directSignCollections[collection]
				
				// Get regular collection token (as fallback)
				token, err := app.getTokenCached(collection)
				if err != nil {
					log.Printf("Error getting token for collection %s: %v", collection, err)
				}
				
				var directSignToken string
				// Not using foundFirstAsset here because we're doing a two-pass approach
				// for ItemCollections rather than tracking the first asset as we go
				
				// Sign all asset URLs
				modified := false
				for _, assetData := range assets {
					if asset, ok := assetData.(map[string]interface{}); ok {
						if href, hasHref := asset["href"].(string); hasHref {
							if strings.Contains(href, ".blob.core.windows.net") && !app.isURLSigned(href) {
								if !strings.Contains(href, "ai4edatasetspublicassets.blob.core.windows.net") {
									if needsDirectSigning {
										// For directly signed collections:
										// For the first asset, get or create a direct token
										var err error
										directSignToken, err = app.getDirectSignTokenCached(collection, href)
										if err != nil {
											log.Printf("Error getting direct token, falling back to collection token: %v", err)
											asset["href"] = href + "?" + token
										} else {
											// Apply the token
											asset["href"] = href + "?" + directSignToken
										}
									} else {
										// Use collection token (original approach)
										asset["href"] = href + "?" + token
									}
									modified = true
								}
							}
						}
					}
				}
				
				if modified {
					// Re-encode the JSON with signed URLs
					signedJSON, err := json.Marshal(data)
					if err != nil {
						return content, fmt.Errorf("marshaling signed STAC item: %w", err)
					}
					log.Printf("Signed all assets in STAC Item")
					return string(signedJSON), nil
				}
			}
		}
	}
	
	// Also check for STAC ItemCollection
	if t, ok := data["type"].(string); ok && t == "FeatureCollection" {
		if features, hasFeatures := data["features"].([]interface{}); hasFeatures {
			// Get regular collection token (as fallback)
			token, err := app.getTokenCached(collection)
			if err != nil {
				return content, fmt.Errorf("getting token for STAC item collection signing: %w", err)
			}
			
			// Check if this collection needs direct signing
			needsDirectSigning := app.directSignCollections[collection]
			
			var directSignToken string
			// Not using foundFirstAsset here because we're doing a two-pass approach
			// for ItemCollections rather than tracking the first asset as we go
			
			// Sign assets in all features
			modified := false
			
			// First pass: find an asset to use for direct signing if needed
			firstAssetURL := ""
			if needsDirectSigning {
				for _, featureData := range features {
					if feature, ok := featureData.(map[string]interface{}); ok {
						if assets, hasAssets := feature["assets"].(map[string]interface{}); hasAssets {
							for _, assetData := range assets {
								if asset, ok := assetData.(map[string]interface{}); ok {
									if href, hasHref := asset["href"].(string); hasHref {
										if strings.Contains(href, ".blob.core.windows.net") && 
										   !app.isURLSigned(href) && 
										   !strings.Contains(href, "ai4edatasetspublicassets.blob.core.windows.net") {
											firstAssetURL = href
											break
										}
									}
								}
							}
							if firstAssetURL != "" {
								break
							}
						}
					}
					if firstAssetURL != "" {
						break
					}
				}
				
				// If we found a good asset URL, get a direct token for it
				if firstAssetURL != "" {
					var err error
					directSignToken, err = app.getDirectSignTokenCached(collection, firstAssetURL)
					if err != nil {
						log.Printf("Error getting direct token for ItemCollection, falling back to collection token: %v", err)
						// Continue with the collection token as fallback
					}
				}
			}
			
			// Second pass: apply tokens to all assets
			for _, featureData := range features {
				if feature, ok := featureData.(map[string]interface{}); ok {
					if assets, hasAssets := feature["assets"].(map[string]interface{}); hasAssets {
						for _, assetData := range assets {
							if asset, ok := assetData.(map[string]interface{}); ok {
								if href, hasHref := asset["href"].(string); hasHref {
									if strings.Contains(href, ".blob.core.windows.net") && !app.isURLSigned(href) {
										if !strings.Contains(href, "ai4edatasetspublicassets.blob.core.windows.net") {
											if needsDirectSigning && directSignToken != "" {
												// Use the direct token we obtained earlier
												asset["href"] = href + "?" + directSignToken
											} else {
												// Use collection token (either not direct signing or failed to get direct token)
												asset["href"] = href + "?" + token
											}
											modified = true
										}
									}
								}
							}
						}
					}
				}
			}
			
			if modified {
				// Re-encode the JSON with signed URLs
				signedJSON, err := json.Marshal(data)
				if err != nil {
					return content, fmt.Errorf("marshaling signed STAC item collection: %w", err)
				}
				log.Printf("Signed all assets in STAC ItemCollection")
				return string(signedJSON), nil
			}
		}
	}
	
	// Not a recognized STAC structure or no modifications needed
	return content, nil
}
