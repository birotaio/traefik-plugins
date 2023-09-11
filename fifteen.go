package traefik_plugins

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type FallbackType string

const (
	FallbackError  FallbackType = "error"
	FallbackPass   FallbackType = "pass"
	FallbackIp     FallbackType = "ip"
	FallbackHeader FallbackType = "header"
)

type Fallback struct {
	Type        FallbackType `yaml:"type,omitempty"`
	Value       string       `yaml:"value,omitempty"`
	KeepIfEmpty bool         `yaml:"keepIfEmpty,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	JwtHeaderName   string     `yaml:"jwtHeaderName,omitempty"`
	JwtField        string     `yaml:"jwtField,omitempty"`
	ValueHeaderName string     `yaml:"valueHeaderName,omitempty"`
	Fallbacks       []Fallback `yaml:"fallbacks,omitempty"`
	Debug           bool       `yaml:"debug,omitempty"`
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

	rawHeader := req.Header.Get(a.cfg.JwtHeaderName)
	rawToken := ""
	if strings.HasPrefix(rawHeader, "Bearer ") {
		rawToken = rawHeader[len("Bearer "):]
	}
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
		a.logDebug("JWT field value does not hold field %s, falling back", a.cfg.JwtField)
		a.ServeFallback(rw, req)
		return
	}

	a.end(rw, req)
}

func (a *Fifteen) ServeFallback(rw http.ResponseWriter, req *http.Request) {
	if len(a.cfg.Fallbacks) == 0 {
		a.logDebug("Fallbacked because JWT was not set, invalid or has unexpected value on field. No fallback strategies, ignoring...")
	} else {
		a.logDebug("Fallbacked because JWT was not set, invalid or has unexpected value on field. Finding right fallback strategy")
		for i, fallback := range a.cfg.Fallbacks {
			a.logDebug("Strategy %d: %+v", i, fallback)
			var success bool
			switch fallback.Type {
			case FallbackError:
				rw.Header().Set("Content-Type", "text/plain")
				rw.WriteHeader(http.StatusBadRequest)
				rw.Write([]byte("Bad request"))
				return
			case FallbackPass:
				a.logDebug("Passing through")
				success = true
			case FallbackIp:
				req.Header.Set(a.cfg.ValueHeaderName, ipWithNoPort(req.RemoteAddr))
				success = true
			case FallbackHeader:
				headerValue := req.Header.Get(fallback.Value)
				if headerValue == "" && !fallback.KeepIfEmpty {
					a.logDebug("Header %s was empty, skipping...", fallback.Value)
					continue
				}
				req.Header.Set(a.cfg.ValueHeaderName, headerValue)
				success = true
			default:
				a.logDebug("Unknown fallback type, skipping...")
			}
			if success {
				a.logDebug("Fallback strategy %d was successful", i)
				break
			}
		}
	}
	a.end(rw, req)
}

func (a *Fifteen) logDebug(format string, args ...any) {
	if !a.cfg.Debug {
		return
	}
	os.Stderr.WriteString("[Fifteen middleware]: " + fmt.Sprintf(format, args...) + "\n")
}

func (a *Fifteen) end(rw http.ResponseWriter, req *http.Request) {
	a.logDebug("ending with request headers: %+v", req.Header)
	a.next.ServeHTTP(rw, req)
}

func ipWithNoPort(addr string) string {
	if colon := strings.LastIndex(addr, ":"); colon != -1 {
		return addr[:colon]
	}
	return addr
}
