package traefikplugins

import (
	"context"
	"fmt"
	"net/http"
	"os"

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
	JwtHeaderName      string   `json:"jwt-header-name,omitempty"`
	JwtField           string   `json:"jwt-field,omitempty"`
	ValueHeaderName    string   `json:"value-header-name,omitempty"`
	FallbackType       Fallback `json:"fallback-type,omitempty"`
	FallbackHeaderName string   `json:"fallback-header-name,omitempty"`
	Debug              bool     `json:"debug,omitempty"`
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
	if req.Header.Get(a.cfg.JwtHeaderName) == "" {
		a.logDebug("Empty jwt, falling back")
		a.ServeFallback(rw, req)
		return
	}

	rawToken := req.Header.Get(a.cfg.JwtHeaderName)
	parsedToken, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		a.logDebug("Could not parse non-empty jwt token, falling back: %s", err.Error())
		a.ServeFallback(rw, req)
		return
	}

	mapClaims := parsedToken.Claims.(jwt.MapClaims)
	if newHeaderValue, hasValue := mapClaims[a.cfg.JwtField]; hasValue {
		a.logDebug("JWT value on field %s was %v (of type %T)", a.cfg.JwtField, newHeaderValue, newHeaderValue)
		switch val := newHeaderValue.(type) {
		case string:
			req.Header.Set(a.cfg.ValueHeaderName, val)
		case []string:
			if len(val) > 0 {
				req.Header.Set(a.cfg.ValueHeaderName, val[0])
			} else {
				a.logDebug("JWT field value was an empty array, falling back")
				a.ServeFallback(rw, req)
				return
			}
		default:
			a.logDebug("JWT field value has an unexpected type, falling back")
			a.ServeFallback(rw, req)
			return
		}
	} else {
		a.logDebug("JWT field value has an unexpected type, falling back")
		a.ServeFallback(rw, req)
		return
	}

	a.next.ServeHTTP(rw, req)
}

func (a *Fifteen) ServeFallback(rw http.ResponseWriter, req *http.Request) {
	a.logDebug("Fallbacked because JWT was not set, invalid or has unexpected value on field. Using fallback strategy: %s", a.cfg.FallbackType)
	switch a.cfg.FallbackType {
	case FallbackError:
		rw.WriteHeader(http.StatusBadRequest)
	case FallbackIp:
		req.Header.Set(a.cfg.ValueHeaderName, req.RemoteAddr)
	case FallbackHeader:
		req.Header.Set(a.cfg.ValueHeaderName, req.Header.Get(a.cfg.FallbackHeaderName))
	default:
		a.next.ServeHTTP(rw, req)
	}
}

func (a *Fifteen) logDebug(format string, args ...any) {
	if !a.cfg.Debug {
		return
	}
	os.Stderr.WriteString("[Fifteen middleware]: " + fmt.Sprintf(format, args...) + "\n")
}
