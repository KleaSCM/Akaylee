/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: api.go
Description: Core interfaces for API fuzzing support. Defines HTTP targets, REST APIs,
GraphQL endpoints, network protocols, authentication, and session management for
comprehensive API security testing and vulnerability discovery.
*/

package interfaces

import (
	"context"
	"time"
)

// APITargetType represents the type of API target
type APITargetType string

const (
	APITargetTypeHTTP      APITargetType = "http"
	APITargetTypeREST      APITargetType = "rest"
	APITargetTypeGraphQL   APITargetType = "graphql"
	APITargetTypeTCP       APITargetType = "tcp"
	APITargetTypeUDP       APITargetType = "udp"
	APITargetTypeWebSocket APITargetType = "websocket"
)

// HTTPMethod represents HTTP methods for API fuzzing
type HTTPMethod string

const (
	HTTPMethodGET     HTTPMethod = "GET"
	HTTPMethodPOST    HTTPMethod = "POST"
	HTTPMethodPUT     HTTPMethod = "PUT"
	HTTPMethodDELETE  HTTPMethod = "DELETE"
	HTTPMethodPATCH   HTTPMethod = "PATCH"
	HTTPMethodHEAD    HTTPMethod = "HEAD"
	HTTPMethodOPTIONS HTTPMethod = "OPTIONS"
)

// APITarget represents an API endpoint to fuzz
type APITarget struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       APITargetType          `json:"type"`
	URL        string                 `json:"url"`
	Method     HTTPMethod             `json:"method"`
	Headers    map[string]string      `json:"headers"`
	Parameters []APIParameter         `json:"parameters"`
	Body       []byte                 `json:"body"`
	Auth       *APIAuth               `json:"auth,omitempty"`
	Timeout    time.Duration          `json:"timeout"`
	Retries    int                    `json:"retries"`
	RateLimit  *APIRateLimit          `json:"rate_limit,omitempty"`
	Validation *APIValidation         `json:"validation,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// APIParameter represents a parameter in an API request
type APIParameter struct {
	Name        string                `json:"name"`
	Type        string                `json:"type"` // query, path, header, body
	Required    bool                  `json:"required"`
	Default     interface{}           `json:"default"`
	Constraints *ParameterConstraints `json:"constraints,omitempty"`
	Description string                `json:"description"`
}

// ParameterConstraints defines validation constraints for parameters
type ParameterConstraints struct {
	MinLength int           `json:"min_length,omitempty"`
	MaxLength int           `json:"max_length,omitempty"`
	MinValue  float64       `json:"min_value,omitempty"`
	MaxValue  float64       `json:"max_value,omitempty"`
	Pattern   string        `json:"pattern,omitempty"`
	Enum      []interface{} `json:"enum,omitempty"`
	Format    string        `json:"format,omitempty"` // email, url, uuid, etc.
}

// APIAuth represents authentication configuration
type APIAuth struct {
	Type         string            `json:"type"` // basic, bearer, oauth, api_key, etc.
	Credentials  map[string]string `json:"credentials"`
	TokenURL     string            `json:"token_url,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"`
}

// APIRateLimit represents rate limiting configuration
type APIRateLimit struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	Window            time.Duration `json:"window"`
}

// APIValidation represents response validation rules
type APIValidation struct {
	ExpectedStatusCodes []int         `json:"expected_status_codes"`
	RequiredHeaders     []string      `json:"required_headers"`
	RequiredFields      []string      `json:"required_fields"`
	MaxResponseSize     int64         `json:"max_response_size"`
	Timeout             time.Duration `json:"timeout"`
	Schema              interface{}   `json:"schema,omitempty"`
}

// APIRequest represents an API request to be fuzzed
type APIRequest struct {
	ID          string                 `json:"id"`
	TargetID    string                 `json:"target_id"`
	Method      HTTPMethod             `json:"method"`
	URL         string                 `json:"url"`
	Headers     map[string]string      `json:"headers"`
	QueryParams map[string]string      `json:"query_params"`
	PathParams  map[string]string      `json:"path_params"`
	Body        []byte                 `json:"body"`
	BodyType    string                 `json:"body_type"` // json, xml, form, raw
	Auth        *APIAuth               `json:"auth,omitempty"`
	Timeout     time.Duration          `json:"timeout"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// APIResponse represents an API response
type APIResponse struct {
	StatusCode    int                    `json:"status_code"`
	Headers       map[string]string      `json:"headers"`
	Body          []byte                 `json:"body"`
	ContentType   string                 `json:"content_type"`
	ContentLength int64                  `json:"content_length"`
	Duration      time.Duration          `json:"duration"`
	Error         string                 `json:"error,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// APIExecutionResult extends ExecutionResult with API-specific information
type APIExecutionResult struct {
	*ExecutionResult
	Request            *APIRequest  `json:"request"`
	Response           *APIResponse `json:"response"`
	AuthValid          bool         `json:"auth_valid"`
	RateLimited        bool         `json:"rate_limited"`
	ValidationPass     bool         `json:"validation_pass"`
	APISpecificCrashes []APICrash   `json:"api_specific_crashes"`
}

// APICrash represents API-specific crash information
type APICrash struct {
	Type        string                 `json:"type"` // auth_bypass, injection, dos, etc.
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Payload     string                 `json:"payload"`
	Endpoint    string                 `json:"endpoint"`
	Method      HTTPMethod             `json:"method"`
	StatusCode  int                    `json:"status_code"`
	Evidence    map[string]interface{} `json:"evidence"`
}

// APISession represents a session for stateful API testing
type APISession struct {
	ID           string                 `json:"id"`
	TargetID     string                 `json:"target_id"`
	Cookies      map[string]string      `json:"cookies"`
	Headers      map[string]string      `json:"headers"`
	Tokens       map[string]string      `json:"tokens"`
	State        map[string]interface{} `json:"state"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	Valid        bool                   `json:"valid"`
}

// APIFuzzerConfig extends FuzzerConfig with API-specific settings
type APIFuzzerConfig struct {
	*FuzzerConfig
	Targets            []*APITarget      `json:"targets"`
	ConcurrentRequests int               `json:"concurrent_requests"`
	RequestTimeout     time.Duration     `json:"request_timeout"`
	FollowRedirects    bool              `json:"follow_redirects"`
	VerifySSL          bool              `json:"verify_ssl"`
	Proxy              string            `json:"proxy,omitempty"`
	UserAgent          string            `json:"user_agent"`
	RateLimit          *APIRateLimit     `json:"rate_limit,omitempty"`
	SessionManagement  *SessionConfig    `json:"session_management,omitempty"`
	InjectionPayloads  []string          `json:"injection_payloads"`
	CustomHeaders      map[string]string `json:"custom_headers"`
}

// SessionConfig represents session management configuration
type SessionConfig struct {
	EnableSessions     bool                   `json:"enable_sessions"`
	SessionTimeout     time.Duration          `json:"session_timeout"`
	MaxSessions        int                    `json:"max_sessions"`
	SessionPersistence bool                   `json:"session_persistence"`
	SessionData        map[string]interface{} `json:"session_data"`
}

// APIExecutor extends Executor for API-specific execution
type APIExecutor interface {
	Executor
	ExecuteAPIRequest(ctx context.Context, request *APIRequest) (*APIExecutionResult, error)
	ExecuteAPIBatch(ctx context.Context, requests []*APIRequest) ([]*APIExecutionResult, error)
	ValidateTarget(target *APITarget) error
	GetSession(sessionID string) (*APISession, error)
	CreateSession(targetID string) (*APISession, error)
	UpdateSession(session *APISession) error
	CloseSession(sessionID string) error
}

// APIMutator extends Mutator for API-specific mutations
type APIMutator interface {
	Mutator
	MutateAPIRequest(request *APIRequest) (*APIRequest, error)
	MutateHeaders(headers map[string]string) (map[string]string, error)
	MutateQueryParams(params map[string]string) (map[string]string, error)
	MutatePathParams(params map[string]string) (map[string]string, error)
	MutateBody(body []byte, contentType string) ([]byte, error)
	GenerateInjectionPayloads() []string
	GenerateAuthBypassPayloads() []string
}

// APIAnalyzer extends Analyzer for API-specific analysis
type APIAnalyzer interface {
	Analyzer
	AnalyzeAPIResponse(result *APIExecutionResult) error
	DetectAPIVulnerabilities(result *APIExecutionResult) ([]APICrash, error)
	ValidateResponse(response *APIResponse, validation *APIValidation) (bool, []string, error)
	DetectRateLimiting(response *APIResponse) bool
	DetectAuthenticationBypass(result *APIExecutionResult) bool
	DetectInjectionVulnerabilities(result *APIExecutionResult) ([]APICrash, error)
}

// APIDiscovery represents API endpoint discovery
type APIDiscovery interface {
	DiscoverEndpoints(baseURL string) ([]*APITarget, error)
	ParseOpenAPI(spec []byte) ([]*APITarget, error)
	ParseGraphQLSchema(schema []byte) ([]*APITarget, error)
	ParseSwagger(spec []byte) ([]*APITarget, error)
	BruteForceEndpoints(baseURL string, wordlist []string) ([]*APITarget, error)
}

// APIPayloadGenerator generates fuzzing payloads for APIs
type APIPayloadGenerator interface {
	GenerateSQLInjectionPayloads() []string
	GenerateXSSPayloads() []string
	GenerateCommandInjectionPayloads() []string
	GeneratePathTraversalPayloads() []string
	GenerateAuthenticationBypassPayloads() []string
	GenerateRateLimitBypassPayloads() []string
	GenerateCustomPayloads(payloadType string) []string
}
