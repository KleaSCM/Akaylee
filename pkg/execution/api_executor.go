/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: api_executor.go
Description: HTTP API executor for comprehensive API fuzzing. Handles REST APIs,
GraphQL endpoints, authentication, session management, rate limiting, and
vulnerability detection for web services and network protocols.
*/

package execution

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// HTTPAPIExecutor implements APIExecutor for HTTP-based APIs
type HTTPAPIExecutor struct {
	client       *http.Client
	sessions     map[string]*interfaces.APISession
	sessionMutex sync.RWMutex
	rateLimiter  *RateLimiter
	logger       *logrus.Logger
	config       *interfaces.APIFuzzerConfig
	authTokens   map[string]string
	authMutex    sync.RWMutex
}

// RateLimiter implements rate limiting for API requests
type RateLimiter struct {
	requestsPerSecond int
	burstSize         int
	window            time.Duration
	tokens            chan struct{}
	lastRefill        time.Time
	mutex             sync.Mutex
}

// NewHTTPAPIExecutor creates a new HTTP API executor
func NewHTTPAPIExecutor(config *interfaces.APIFuzzerConfig, logger *logrus.Logger) *HTTPAPIExecutor {
	// Create HTTP client with custom configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	executor := &HTTPAPIExecutor{
		client:     client,
		sessions:   make(map[string]*interfaces.APISession),
		logger:     logger,
		config:     config,
		authTokens: make(map[string]string),
	}

	// Setup rate limiter if configured
	if config.RateLimit != nil {
		executor.rateLimiter = NewRateLimiter(
			config.RateLimit.RequestsPerSecond,
			config.RateLimit.BurstSize,
			config.RateLimit.Window,
		)
	}

	return executor
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond, burstSize int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requestsPerSecond: requestsPerSecond,
		burstSize:         burstSize,
		window:            window,
		tokens:            make(chan struct{}, burstSize),
		lastRefill:        time.Now(),
	}

	// Fill initial tokens
	for i := 0; i < burstSize; i++ {
		rl.tokens <- struct{}{}
	}

	// Start token refill goroutine
	go rl.refillTokens()

	return rl
}

// refillTokens refills the token bucket
func (rl *RateLimiter) refillTokens() {
	ticker := time.NewTicker(rl.window / time.Duration(rl.requestsPerSecond))
	defer ticker.Stop()

	for range ticker.C {
		rl.mutex.Lock()
		select {
		case rl.tokens <- struct{}{}:
			// Token added successfully
		default:
			// Bucket is full
		}
		rl.mutex.Unlock()
	}
}

// WaitForToken waits for a token to become available
func (rl *RateLimiter) WaitForToken(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Initialize sets up the API executor
func (e *HTTPAPIExecutor) Initialize(config *interfaces.FuzzerConfig) error {
	e.logger.Info("Initializing HTTP API executor")
	return nil
}

// ExecuteAPIRequest executes a single API request
func (e *HTTPAPIExecutor) ExecuteAPIRequest(ctx context.Context, request *interfaces.APIRequest) (*interfaces.APIExecutionResult, error) {
	startTime := time.Now()

	// Apply rate limiting if configured
	if e.rateLimiter != nil {
		if err := e.rateLimiter.WaitForToken(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait failed: %w", err)
		}
	}

	// Create HTTP request
	httpReq, err := e.createHTTPRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Execute request
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Create API response
	apiResp := &interfaces.APIResponse{
		StatusCode:    resp.StatusCode,
		Headers:       e.convertHeaders(resp.Header),
		Body:          body,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Duration:      time.Since(startTime),
	}

	// Create execution result
	result := &interfaces.APIExecutionResult{
		ExecutionResult: &interfaces.ExecutionResult{
			TestCaseID:  request.ID,
			Status:      e.determineStatus(resp.StatusCode),
			ExitCode:    resp.StatusCode,
			Output:      body,
			Duration:    time.Since(startTime),
			MemoryUsage: uint64(len(body)),
		},
		Request:        request,
		Response:       apiResp,
		AuthValid:      e.validateAuth(resp),
		RateLimited:    e.isRateLimited(resp),
		ValidationPass: e.validateResponse(apiResp),
	}

	// Detect API-specific vulnerabilities
	crashes, err := e.detectVulnerabilities(result)
	if err != nil {
		e.logger.Warnf("Vulnerability detection failed: %v", err)
	} else {
		result.APISpecificCrashes = crashes
	}

	return result, nil
}

// ExecuteAPIBatch executes multiple API requests concurrently
func (e *HTTPAPIExecutor) ExecuteAPIBatch(ctx context.Context, requests []*interfaces.APIRequest) ([]*interfaces.APIExecutionResult, error) {
	results := make([]*interfaces.APIExecutionResult, len(requests))
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Create semaphore for concurrent requests
	semaphore := make(chan struct{}, e.config.ConcurrentRequests)

	for i, request := range requests {
		wg.Add(1)
		go func(index int, req *interfaces.APIRequest) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Execute request
			result, err := e.ExecuteAPIRequest(ctx, req)
			if err != nil {
				e.logger.Errorf("Batch request %d failed: %v", index, err)
				return
			}

			// Store result
			mu.Lock()
			results[index] = result
			mu.Unlock()
		}(i, request)
	}

	wg.Wait()

	// Filter out nil results
	validResults := make([]*interfaces.APIExecutionResult, 0, len(results))
	for _, result := range results {
		if result != nil {
			validResults = append(validResults, result)
		}
	}

	return validResults, nil
}

// createHTTPRequest creates an HTTP request from an API request
func (e *HTTPAPIExecutor) createHTTPRequest(ctx context.Context, request *interfaces.APIRequest) (*http.Request, error) {
	// Always use the configured target URL, not the mutated request's URL
	urlToUse := ""
	if len(e.config.Targets) > 0 {
		urlToUse = e.config.Targets[0].URL
	} else {
		return nil, fmt.Errorf("no configured target URL in API executor")
	}
	parsedURL, err := url.Parse(urlToUse)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Add query parameters
	query := parsedURL.Query()
	for key, value := range request.QueryParams {
		query.Set(key, value)
	}
	parsedURL.RawQuery = query.Encode()

	// Create request
	httpReq, err := http.NewRequestWithContext(ctx, string(request.Method), parsedURL.String(), bytes.NewReader(request.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	for key, value := range request.Headers {
		httpReq.Header.Set(key, value)
	}

	// Set custom headers from config
	for key, value := range e.config.CustomHeaders {
		if httpReq.Header.Get(key) == "" {
			httpReq.Header.Set(key, value)
		}
	}

	// Set User-Agent
	if e.config.UserAgent != "" {
		httpReq.Header.Set("User-Agent", e.config.UserAgent)
	}

	// Apply authentication
	if err := e.applyAuthentication(httpReq, request.Auth); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Set content type for body
	if len(request.Body) > 0 {
		contentType := request.BodyType
		if contentType == "" {
			contentType = "application/json"
		}
		httpReq.Header.Set("Content-Type", contentType)
	}

	return httpReq, nil
}

// applyAuthentication applies authentication to the request
func (e *HTTPAPIExecutor) applyAuthentication(req *http.Request, auth *interfaces.APIAuth) error {
	if auth == nil {
		return nil
	}

	switch auth.Type {
	case "basic":
		username := auth.Credentials["username"]
		password := auth.Credentials["password"]
		req.SetBasicAuth(username, password)

	case "bearer":
		token := auth.Credentials["token"]
		req.Header.Set("Authorization", "Bearer "+token)

	case "api_key":
		key := auth.Credentials["key"]
		header := auth.Credentials["header"]
		if header == "" {
			header = "X-API-Key"
		}
		req.Header.Set(header, key)

	case "oauth":
		// Handle OAuth token refresh if needed
		token, err := e.getOAuthToken(auth)
		if err != nil {
			return fmt.Errorf("OAuth token retrieval failed: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}

	return nil
}

// getOAuthToken retrieves or refreshes OAuth token
func (e *HTTPAPIExecutor) getOAuthToken(auth *interfaces.APIAuth) (string, error) {
	// Check if we have a cached token
	e.authMutex.RLock()
	if token, exists := e.authTokens[auth.TokenURL]; exists {
		e.authMutex.RUnlock()
		return token, nil
	}
	e.authMutex.RUnlock()

	// Request new token
	credentials := url.Values{}
	credentials.Set("grant_type", "client_credentials")
	credentials.Set("client_id", auth.Credentials["client_id"])
	credentials.Set("client_secret", auth.Credentials["client_secret"])

	resp, err := http.PostForm(auth.TokenURL, credentials)
	if err != nil {
		return "", fmt.Errorf("OAuth token request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode OAuth response: %w", err)
	}

	// Cache the token
	e.authMutex.Lock()
	e.authTokens[auth.TokenURL] = tokenResp.AccessToken
	e.authMutex.Unlock()

	return tokenResp.AccessToken, nil
}

// convertHeaders converts http.Header to map[string]string
func (e *HTTPAPIExecutor) convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

// determineStatus determines execution status from HTTP status code
func (e *HTTPAPIExecutor) determineStatus(statusCode int) interfaces.ExecutionStatus {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return interfaces.StatusSuccess
	case statusCode >= 400 && statusCode < 500:
		return interfaces.StatusError
	case statusCode >= 500:
		return interfaces.StatusCrash
	default:
		return interfaces.StatusError
	}
}

// validateAuth validates authentication based on response
func (e *HTTPAPIExecutor) validateAuth(resp *http.Response) bool {
	// Check for authentication-related status codes
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}

	// Check for authentication-related headers
	authHeaders := []string{"WWW-Authenticate", "X-Auth-Required"}
	for _, header := range authHeaders {
		if resp.Header.Get(header) != "" {
			return false
		}
	}

	return true
}

// isRateLimited checks if response indicates rate limiting
func (e *HTTPAPIExecutor) isRateLimited(resp *http.Response) bool {
	// Check status codes
	if resp.StatusCode == 429 {
		return true
	}

	// Check rate limit headers
	rateLimitHeaders := []string{"X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"}
	for _, header := range rateLimitHeaders {
		if resp.Header.Get(header) != "" {
			return true
		}
	}

	return false
}

// validateResponse validates response against expected criteria
func (e *HTTPAPIExecutor) validateResponse(response *interfaces.APIResponse) bool {
	// Basic validation - can be extended with more sophisticated rules
	return response.StatusCode >= 200 && response.StatusCode < 500
}

// detectVulnerabilities detects API-specific vulnerabilities
func (e *HTTPAPIExecutor) detectVulnerabilities(result *interfaces.APIExecutionResult) ([]interfaces.APICrash, error) {
	var crashes []interfaces.APICrash

	// Check for SQL injection indicators
	if e.detectSQLInjection(result) {
		crashes = append(crashes, interfaces.APICrash{
			Type:        "sql_injection",
			Severity:    "high",
			Description: "Potential SQL injection vulnerability detected",
			Payload:     string(result.Request.Body),
			Endpoint:    result.Request.URL,
			Method:      result.Request.Method,
			StatusCode:  result.Response.StatusCode,
		})
	}

	// Check for XSS indicators
	if e.detectXSS(result) {
		crashes = append(crashes, interfaces.APICrash{
			Type:        "xss",
			Severity:    "medium",
			Description: "Potential XSS vulnerability detected",
			Payload:     string(result.Request.Body),
			Endpoint:    result.Request.URL,
			Method:      result.Request.Method,
			StatusCode:  result.Response.StatusCode,
		})
	}

	// Check for authentication bypass
	if e.detectAuthBypass(result) {
		crashes = append(crashes, interfaces.APICrash{
			Type:        "auth_bypass",
			Severity:    "critical",
			Description: "Potential authentication bypass detected",
			Payload:     string(result.Request.Body),
			Endpoint:    result.Request.URL,
			Method:      result.Request.Method,
			StatusCode:  result.Response.StatusCode,
		})
	}

	return crashes, nil
}

// detectSQLInjection detects SQL injection vulnerabilities
func (e *HTTPAPIExecutor) detectSQLInjection(result *interfaces.APIExecutionResult) bool {
	// Check for SQL error messages in response
	sqlErrors := []string{
		"sql syntax", "mysql_fetch", "oracle error", "postgresql error",
		"sql server", "sqlite error", "database error", "syntax error",
	}

	responseBody := strings.ToLower(string(result.Response.Body))
	for _, errorMsg := range sqlErrors {
		if strings.Contains(responseBody, errorMsg) {
			return true
		}
	}

	return false
}

// detectXSS detects XSS vulnerabilities
func (e *HTTPAPIExecutor) detectXSS(result *interfaces.APIExecutionResult) bool {
	// Check if XSS payload is reflected in response
	xssPayloads := []string{"<script>", "javascript:", "onerror=", "onload="}

	responseBody := strings.ToLower(string(result.Response.Body))
	for _, payload := range xssPayloads {
		if strings.Contains(responseBody, payload) {
			return true
		}
	}

	return false
}

// detectAuthBypass detects authentication bypass vulnerabilities
func (e *HTTPAPIExecutor) detectAuthBypass(result *interfaces.APIExecutionResult) bool {
	// Check if unauthorized request returns sensitive data
	if result.Response.StatusCode == 200 && len(result.Response.Body) > 100 {
		// Look for sensitive data patterns
		sensitivePatterns := []string{
			"password", "token", "secret", "key", "credential",
			"admin", "user", "email", "phone", "ssn",
		}

		responseBody := strings.ToLower(string(result.Response.Body))
		for _, pattern := range sensitivePatterns {
			if strings.Contains(responseBody, pattern) {
				return true
			}
		}
	}

	return false
}

// Session management methods

// GetSession retrieves a session by ID
func (e *HTTPAPIExecutor) GetSession(sessionID string) (*interfaces.APISession, error) {
	e.sessionMutex.RLock()
	defer e.sessionMutex.RUnlock()

	session, exists := e.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	return session, nil
}

// CreateSession creates a new session
func (e *HTTPAPIExecutor) CreateSession(targetID string) (*interfaces.APISession, error) {
	session := &interfaces.APISession{
		ID:           uuid.New().String(),
		TargetID:     targetID,
		Cookies:      make(map[string]string),
		Headers:      make(map[string]string),
		Tokens:       make(map[string]string),
		State:        make(map[string]interface{}),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Valid:        true,
	}

	e.sessionMutex.Lock()
	e.sessions[session.ID] = session
	e.sessionMutex.Unlock()

	return session, nil
}

// UpdateSession updates an existing session
func (e *HTTPAPIExecutor) UpdateSession(session *interfaces.APISession) error {
	session.LastActivity = time.Now()

	e.sessionMutex.Lock()
	e.sessions[session.ID] = session
	e.sessionMutex.Unlock()

	return nil
}

// CloseSession closes a session
func (e *HTTPAPIExecutor) CloseSession(sessionID string) error {
	e.sessionMutex.Lock()
	delete(e.sessions, sessionID)
	e.sessionMutex.Unlock()

	return nil
}

// ValidateTarget validates an API target
func (e *HTTPAPIExecutor) ValidateTarget(target *interfaces.APITarget) error {
	// Validate URL
	if target.URL == "" {
		return fmt.Errorf("target URL is required")
	}

	// Validate method
	if target.Method == "" {
		return fmt.Errorf("target method is required")
	}

	// Test connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", target.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// Cleanup cleans up resources
func (e *HTTPAPIExecutor) Cleanup() error {
	e.logger.Info("Cleaning up HTTP API executor")
	return nil
}
