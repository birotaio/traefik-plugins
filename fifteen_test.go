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
	cfg.FallbackType = FallbackIp
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
	req.Header.Set(cfg.JwtHeaderName, "invalid")
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "1.2.3.4")

	// Valid JWT, field value missing, fallback to IP
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	req.Header.Set(cfg.JwtHeaderName, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IGlzc3VlciIsImlhdCI6MTY5NDA5ODQ3NiwiZXhwIjoxNzI1NjM0NDc2LCJhdWQiOiIiLCJzdWIiOiIifQ.898seJ3c8Quryhtwwt_66m_iJQwRVCtt216l1KOhBp8")
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "1.2.3.4")

	// Valid JWT, field value as header
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "1.2.3.4"
	req.Header.Set(cfg.JwtHeaderName, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJUZXN0IGlzc3VlciIsImlhdCI6MTY5NDA5NzQzMywiZXhwIjoxNzI1NjMzNDMzLCJhdWQiOiIiLCJzdWIiOiIiLCJjdXN0b21lcl9pZCI6InNvbWVfdXNlcl9pZCJ9.MuJhmnrPeEsDqcnz3PnTGnY5Z5Zu2nna9FjQF0Me9qU")
	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "X-UserId-RateLimit", "some_user_id")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
