// Package hcaptcha verifies hCaptcha response tokens with Siteverify.
package hcaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	siteverifyEndpoint = "https://api.hcaptcha.com/siteverify"
	defaultTimeout     = time.Second
)

// Result contains the Siteverify response. The basic response includes success
// and error-codes; see https://docs.hcaptcha.com/#verify-the-user-response-server-side.
//
// For example, the usual success check is:
//
//	if result["success"] == true { ... }
type Result map[string]any

// Request contains a Siteverify response token and its optional request data.
// Token is required; RemoteIP and SiteKey are recommended. The account secret
// is passed to New, not included here.
type Request struct {
	// Required.
	Token string

	// Recommended.
	RemoteIP string
	SiteKey  string
}

// Client verifies tokens using the secret passed to New. A Client is safe to
// reuse concurrently by multiple HTTP handlers.
type Client struct {
	secret     string
	endpoint   string
	httpClient *http.Client
}

// New creates a verifier for one non-empty hCaptcha secret.
func New(secret string) (*Client, error) {
	return NewWithHTTPClient(secret, &http.Client{Timeout: defaultTimeout})
}

// NewWithHTTPClient creates a verifier using httpClient without modifying it.
func NewWithHTTPClient(secret string, httpClient *http.Client) (*Client, error) {
	if secret == "" {
		return nil, errors.New("hcaptcha: secret is required")
	}
	if httpClient == nil {
		return nil, errors.New("hcaptcha: http client is required")
	}
	return newClient(secret, siteverifyEndpoint, httpClient), nil
}

func newClient(secret, endpoint string, httpClient *http.Client) *Client {
	clientCopy := &http.Client{
		Transport: httpClient.Transport,
		Jar:       httpClient.Jar,
		Timeout:   httpClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{
		secret: secret, endpoint: endpoint, httpClient: clientCopy,
	}
}

// Verify verifies token using a background context.
func (client *Client) Verify(token string) (Result, error) {
	return client.VerifyContext(context.Background(), token)
}

// VerifyContext verifies token with ctx. Use it in an HTTP handler to stop
// the Siteverify request when the incoming request is cancelled.
func (client *Client) VerifyContext(ctx context.Context, token string) (Result, error) {
	return client.VerifyRequest(ctx, Request{Token: token})
}

// VerifyRequest verifies a token and optional Siteverify request data.
func (client *Client) VerifyRequest(ctx context.Context, request Request) (Result, error) {
	if request.Token == "" {
		return nil, errors.New("hcaptcha: token is required")
	}
	form := url.Values{"secret": {client.secret}, "response": {request.Token}}
	setString(form, "remoteip", request.RemoteIP)
	setString(form, "sitekey", request.SiteKey)
	return client.call(ctx, client.endpoint, form)
}

func setString(form url.Values, name, value string) {
	if value != "" {
		form.Set(name, value)
	}
}

func (client *Client) call(ctx context.Context, endpoint string, form url.Values) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("hcaptcha: create request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("hcaptcha: call siteverify: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	result := Result{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("hcaptcha: decode siteverify response: %w", err)
	}
	return result, nil
}
