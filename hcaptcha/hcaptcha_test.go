package hcaptcha

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyRequestEncodesAllFields(t *testing.T) {
	request := Request{
		Token: "token", RemoteIP: "203.0.113.1", SiteKey: "sitekey",
	}
	want := url.Values{
		"secret": {"secret"}, "response": {"token"}, "remoteip": {"203.0.113.1"}, "sitekey": {"sitekey"},
	}
	server := formServer(t, want)
	defer server.Close()

	result, err := newClient("secret", server.URL, server.Client()).VerifyRequest(context.TODO(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result["success"] != true {
		t.Errorf("result = %#v", result)
	}
}

func TestNew(t *testing.T) {
	client, err := New("secret")
	if err != nil {
		t.Fatal(err)
	}
	if got := client.httpClient.Timeout; got != defaultTimeout {
		t.Errorf("timeout = %v, want %v", got, defaultTimeout)
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name      string
		construct func() (*Client, error)
		want      string
	}{
		{"empty secret", func() (*Client, error) { return New("") }, "hcaptcha: secret is required"},
		{"nil HTTP client", func() (*Client, error) { return NewWithHTTPClient("secret", nil) }, "hcaptcha: http client is required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.construct()
			if err == nil || err.Error() != test.want {
				t.Errorf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestVerifyRejectsEmptyTokenBeforeRequest(t *testing.T) {
	var calls atomic.Int32
	client, err := NewWithHTTPClient("secret", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected request")
	})})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Verify("")
	if err == nil || err.Error() != "hcaptcha: token is required" {
		t.Errorf("error = %v, want token-required error", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("HTTP calls = %d, want 0", got)
	}
}

func TestVerifyAcceptsEvolvingResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, `{"success":"now-a-string","new":{"nested":[1,true,null]},"number":1.5}`)
	}))
	defer server.Close()
	result, err := newClient("secret", server.URL, server.Client()).Verify("token")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result["success"], "now-a-string"; got != want {
		t.Errorf("success = %#v, want %#v", got, want)
	}
	if _, ok := result["new"].(map[string]any); !ok {
		t.Errorf("new = %#v, want object", result["new"])
	}
}

func TestVerifyDoesNotFollowRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		http.Error(w, "redirect target must not be called", http.StatusInternalServerError)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, `{"success":true,"redirect":true}`)
	}))
	defer origin.Close()

	result, err := newClient("secret", origin.URL, origin.Client()).Verify("token")
	if err != nil {
		t.Fatal(err)
	}
	if result["success"] != true || result["redirect"] != true {
		t.Errorf("result = %#v", result)
	}
	if got := targetCalls.Load(); got != 0 {
		t.Errorf("redirect target calls = %d, want 0", got)
	}
}

func TestNewWithHTTPClientPreservesConfiguration(t *testing.T) {
	sentinel := errors.New("original redirect handler")
	source := &http.Client{
		Transport:     http.DefaultTransport,
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return sentinel },
	}
	client, err := NewWithHTTPClient("secret", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.CheckRedirect(nil, nil); !errors.Is(err, sentinel) {
		t.Errorf("source redirect handler changed: %v", err)
	}
	if client.httpClient == source {
		t.Error("HTTP client was not copied")
	}
	if client.httpClient.Transport != source.Transport || client.httpClient.Timeout != source.Timeout {
		t.Error("HTTP client configuration was not preserved")
	}
	if err := client.httpClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("redirect error = %v, want %v", err, http.ErrUseLastResponse)
	}
}

func TestClientCanBeReusedConcurrently(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer server.Close()
	verifier := newClient("secret", server.URL, server.Client())
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := verifier.Verify("token")
			if err != nil || result["success"] != true {
				t.Errorf("Verify() = %#v, %v", result, err)
			}
		}()
	}
	group.Wait()
	if got := calls.Load(); got != 32 {
		t.Errorf("calls = %d, want 32", got)
	}
}

func TestVerifyContextCancellationAndDeadline(t *testing.T) {
	for _, test := range []struct {
		name    string
		context func(context.Context) (context.Context, context.CancelFunc)
		want    error
	}{
		{"cancellation", context.WithCancel, context.Canceled},
		{"deadline", func(ctx context.Context) (context.Context, context.CancelFunc) {
			return context.WithTimeout(ctx, 50*time.Millisecond)
		}, context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				close(started)
				<-release
			}))
			defer server.Close()
			ctx, cancel := test.context(t.Context())
			defer cancel()
			errs := make(chan error, 1)
			go func() {
				_, err := newClient("secret", server.URL, server.Client()).VerifyContext(ctx, "token")
				errs <- err
			}()
			<-started
			if errors.Is(test.want, context.Canceled) {
				cancel()
			}
			err := <-errs
			close(release)
			if !errors.Is(err, test.want) {
				t.Errorf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyReturnsJSONAndTransportErrors(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		if _, err := newClient("secret", "://invalid", http.DefaultClient).Verify("token"); err == nil {
			t.Fatal("Verify() error = nil, want request error")
		}
	})
	t.Run("json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{not-json}`) }))
		defer server.Close()
		if _, err := newClient("secret", server.URL, server.Client()).Verify("token"); err == nil {
			t.Fatal("Verify() error = nil, want JSON error")
		}
	})
	t.Run("transport", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("network unavailable") }), Timeout: time.Second}
		if _, err := newClient("secret", "https://example.test", client).Verify("token"); err == nil {
			t.Fatal("Verify() error = nil, want transport error")
		}
	})
}

func formServer(t *testing.T, want url.Values) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !reflect.DeepEqual(r.PostForm, want) {
			t.Errorf("form = %#v, want %#v", r.PostForm, want)
			http.Error(w, "wrong form", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
