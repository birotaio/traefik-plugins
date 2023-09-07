package traefikplugins

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type Fallback string

const (
	FallbackError  Fallback = "error"
	FallbackPass   Fallback = "pass"
	FallbackIp     Fallback = "ip"
	FallbackHeader Fallback = "header"
)

// Config the plugin configuration.
type Config struct {
	JwtHeaderName      string `json:"jwt-header-name,omitempty"`
	JwtField           string `json:"jwt-field,omitempty"`
	ValueHeaderName    string `json:"value-header-name,omitempty"`
	FallbackType       string `json:"fallback-type,omitempty"`
	FallbackHeaderName string `json:"fallback-header-name,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Fifteen a Fifteen plugin.
type Fifteen struct {
	next http.Handler
	cfg  *Config
	name string
}

// New created a new Fifteen plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Fifteen{
		cfg:  config,
		next: next,
		name: name,
	}, nil
}

func (a *Fifteen) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if rw.Header().Get(a.cfg.JwtHeaderName) == "" {
		a.ServeFallback(rw, req)
		return
	}

	rawToken := rw.Header().Get(a.cfg.JwtHeaderName)
	parsedToken, _, err := jwt.NewParser().ParseUnverified(rawToken, nil)
	if err != nil {
		a.ServeFallback(rw, req)
		return
	}

	mapClaims := parsedToken.Claims.(jwt.MapClaims)
	if newHeaderValue, hasValue := mapClaims[a.cfg.JwtField]; hasValue {
		switch val := newHeaderValue.(type) {
		case string:
			rw.Header().Set(a.cfg.ValueHeaderName, val)
		case []string:
			if len(val) > 0 {
				rw.Header().Set(a.cfg.ValueHeaderName, val[0])
			} else {
				a.ServeFallback(rw, req)
				return
			}
		default:
			a.ServeFallback(rw, req)
			return
		}
	} else {
		a.ServeFallback(rw, req)
		return
	}

	a.next.ServeHTTP(rw, req)
}

func (a *Fifteen) ServeFallback(rw http.ResponseWriter, req *http.Request) {
	switch a.cfg.FallbackType {
	case string(FallbackError):
		rw.WriteHeader(http.StatusBadRequest)
	case string(FallbackIp):
		rw.Header().Set(a.cfg.ValueHeaderName, req.RemoteAddr)
	case string(FallbackHeader):
		rw.Header().Set(a.cfg.ValueHeaderName, req.Header.Get(a.cfg.FallbackHeaderName))
	default:
		a.next.ServeHTTP(rw, req)
	}
}
