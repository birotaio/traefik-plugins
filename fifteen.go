package traefik_plugins

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
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
	ExcludedPaths   []string   `yaml:"excludedPaths,omitempty"`
	AllowedIps      []string   `yaml:"allowedIps,omitempty"`
	// Average is the rate limit in requests per second. 0 disables rate limiting.
	Average int `yaml:"average,omitempty"`
	// Burst is the maximum burst size above the average.
	Burst int  `yaml:"burst,omitempty"`
	Debug bool `yaml:"debug,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

const maxSources = 65536

// Fifteen a Fifteen plugin.
type Fifteen struct {
	next     http.Handler
	cfg      *Config
	name     string
	rtl      rate.Limit
	maxDelay time.Duration
	ttl      int
	buckets  *TtlMap
}

// New created a new Fifteen plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	buckets, err := newTtlMap(maxSources)
	if err != nil {
		return nil, fmt.Errorf("creating ttlmap: %w", err)
	}

	// Initialized at rate.Inf to enforce no rate limiting when config.Average == 0.
	rtl := float64(rate.Inf)
	var maxDelay time.Duration

	if config.Average > 0 {
		rtl = float64(config.Average)
		if rtl < 1 {
			maxDelay = 500 * time.Millisecond
		} else {
			maxDelay = time.Second / (time.Duration(rtl) * 2)
		}
	}

	ttl := 1
	if rtl >= 1 {
		ttl++
	} else if rtl > 0 {
		ttl += int(1 / rtl)
	}

	return &Fifteen{
		cfg:      config,
		next:     next,
		name:     name,
		rtl:      rate.Limit(rtl),
		maxDelay: maxDelay,
		ttl:      ttl,
		buckets:  buckets,
	}, nil
}

// allow returns nil if the request is rate-limited, otherwise the delay to wait.
func (a *Fifteen) allow(key string) *time.Duration {
	var limiter *rate.Limiter
	if rlSource, exists := a.buckets.Get(key); exists {
		limiter = rlSource.(*rate.Limiter)
	} else {
		burst := a.cfg.Burst
		if burst <= 0 {
			burst = a.cfg.Average
		}
		limiter = rate.NewLimiter(a.rtl, burst)
	}

	// Set even when exists to update the expiry time on every activity.
	if err := a.buckets.Set(key, limiter, a.ttl); err != nil {
		return nil
	}

	res := limiter.Reserve()
	if !res.OK() {
		return nil
	}

	delay := res.Delay()
	if delay > a.maxDelay {
		res.Cancel()
	}

	return &delay
}

func (a *Fifteen) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, allowedIp := range a.cfg.AllowedIps {
		if ipWithNoPort(req.RemoteAddr) == allowedIp {
			a.logDebug("Remote address %s is in allowed IPs, passing through", req.RemoteAddr)
			a.next.ServeHTTP(rw, req)
			return
		}
	}

	for _, pattern := range a.cfg.ExcludedPaths {
		if matched, _ := path.Match(pattern, req.URL.Path); matched {
			a.logDebug("Path %s matches excluded pattern %s, passing through", req.URL.Path, pattern)
			a.next.ServeHTTP(rw, req)
			return
		}
	}

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

	key := req.Header.Get(a.cfg.ValueHeaderName)
	if key != "" && a.cfg.Average > 0 {
		delay := a.allow(key)
		if delay == nil {
			a.logDebug("Rate limit exceeded for key %s", key)
			rw.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if *delay > a.maxDelay {
			a.logDebug("Rate limit delay too high for key %s: %s", key, delay)
			rw.WriteHeader(http.StatusTooManyRequests)
			return
		}
	}

	a.next.ServeHTTP(rw, req)
}

func ipWithNoPort(addr string) string {
	if colon := strings.LastIndex(addr, ":"); colon != -1 {
		return addr[:colon]
	}
	return addr
}
