package traefik_plugins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDemo(t *testing.T) {
	cfg := CreateConfig()
	cfg.JwtHeaderName = "X-ApiKey"
	cfg.JwtField = "customer_id"
	cfg.ValueHeaderName = "X-UserId-RateLimit"
	cfg.Fallbacks = []Fallback{
		{Type: FallbackIp},
	}
	cfg.Debug = false

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "traefik-plugins")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	// No JWT, fallback to IP
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "1.2.3.4")

	// Invalid JWT, fallback to IP
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	req.Header.Set(cfg.JwtHeaderName, "Bearer invalid")
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "1.2.3.4")

	// Valid JWT, field value missing, fallback to IP
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	req.Header.Set(cfg.JwtHeaderName, "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IGlzc3VlciIsImlhdCI6MTY5NDA5ODQ3NiwiZXhwIjoxNzI1NjM0NDc2LCJhdWQiOiIiLCJzdWIiOiIifQ.898seJ3c8Quryhtwwt_66m_iJQwRVCtt216l1KOhBp8")
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "1.2.3.4")

	// Valid JWT, field value as header
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	req.Header.Set(cfg.JwtHeaderName, "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IGlzc3VlciIsImlhdCI6MTY5NDA5NzQzMywiZXhwIjoxNzI1NjMzNDMzLCJhdWQiOiIiLCJzdWIiOiIiLCJjdXN0b21lcl9pZCI6InNvbWVfdXNlcl9pZCJ9.MuJhmnrPeEsDqcnz3PnTGnY5Z5Zu2nna9FjQF0Me9qU")
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "some_user_id")
}

func TestExcludedPaths(t *testing.T) {
	cfg := CreateConfig()
	cfg.JwtHeaderName = "X-ApiKey"
	cfg.JwtField = "customer_id"
	cfg.ValueHeaderName = "X-UserId-RateLimit"
	cfg.Fallbacks = []Fallback{
		{Type: FallbackIp},
	}
	cfg.ExcludedPaths = []string{"/assets/*", "/favicon.ico"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "traefik-plugins")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	// Excluded path matching glob: no header set
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/assets/logo.png", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "")

	// Excluded path exact match: no header set
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/favicon.ico", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "")

	// Non-excluded path: normal fallback to IP
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "1.2.3.4")
}

func TestRateLimit(t *testing.T) {
	cfg := CreateConfig()
	cfg.JwtHeaderName = "X-ApiKey"
	cfg.JwtField = "customer_id"
	cfg.ValueHeaderName = "X-Rate-Limit"
	cfg.Fallbacks = []Fallback{{Type: FallbackIp}}
	cfg.Average = 10
	cfg.Burst = 2
	cfg.ExcludedPaths = []string{"/assets/*"}

	ctx := context.Background()

	var statusCodes []int
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		statusCodes = append(statusCodes, http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "traefik-plugins")
	if err != nil {
		t.Fatal(err)
	}

	// Burst of 2: first two requests should pass, third should be rate limited.
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api/data", nil)
		req.RemoteAddr = "1.2.3.4"
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		statusCodes = append([]int{rw.Code}, statusCodes...)
	}

	if statusCodes[0] != http.StatusTooManyRequests {
		t.Errorf("expected 429 on third request, got %d", statusCodes[0])
	}
	if statusCodes[1] != http.StatusOK {
		t.Errorf("expected 200 on second request, got %d", statusCodes[1])
	}
	if statusCodes[2] != http.StatusOK {
		t.Errorf("expected 200 on first request, got %d", statusCodes[2])
	}

	// Excluded paths must never be rate limited even after burst exhausted.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/assets/logo.png", nil)
	req.RemoteAddr = "1.2.3.4"
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Errorf("excluded path should not be rate limited, got %d", rw.Code)
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
