package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type TokenProvider struct {
	current atomic.Pointer[string]
}

func NewTokenProvider(initial string) *TokenProvider {
	tp := &TokenProvider{}
	tp.Set(initial)
	return tp
}

func (tp *TokenProvider) Set(token string) {
	v := token
	tp.current.Store(&v)
}

func (tp *TokenProvider) Get() string {
	p := tp.current.Load()
	if p == nil {
		return ""
	}
	return *p
}

func (tp *TokenProvider) Fingerprint() string {
	t := tp.Get()
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])[:16]
}

func authBearerDynamic(tp *TokenProvider) gin.HandlerFunc {
	if tp == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		expected := tp.Get()
		if expected == "" {
			c.Next()
			return
		}
		header := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		got := []byte(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
		if subtle.ConstantTimeCompare(got, []byte(expected)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
			return
		}
		c.Next()
	}
}

type peerCredContextKey struct{}

func csrfOriginGuard(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.ToLower(o)] = struct{}{}
	}
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		origin := c.GetHeader("Origin")
		if origin == "" {
			ref := c.GetHeader("Referer")
			if ref == "" {
				c.Next()
				return
			}
			u, err := url.Parse(ref)
			if err == nil && strings.EqualFold(u.Host, c.Request.Host) {
				c.Next()
				return
			}
			if _, ok := allowed[strings.ToLower(ref)]; ok {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-origin request blocked"})
			return
		}
		u, err := url.Parse(origin)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid Origin"})
			return
		}
		if strings.EqualFold(u.Host, c.Request.Host) {
			c.Next()
			return
		}
		if _, ok := allowed[strings.ToLower(origin)]; ok {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-origin request blocked"})
	}
}

type rateLimiter struct {
	rps     float64
	burst   int
	mu      sync.Mutex
	buckets map[string]*limiterEntry
}

type limiterEntry struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newRateLimiter(rps float64, burst int) *rateLimiter {
	return &rateLimiter{rps: rps, burst: burst, buckets: make(map[string]*limiterEntry)}
}

func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.buckets[key]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(rate.Limit(rl.rps), rl.burst)}
		rl.buckets[key] = e
	}
	e.seen = now
	for k, v := range rl.buckets {
		if now.Sub(v.seen) > 10*time.Minute {
			delete(rl.buckets, k)
		}
	}
	return e.limiter.Allow()
}

func (rl *rateLimiter) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		key := c.GetHeader("Authorization")
		if key == "" {
			key = c.ClientIP()
		}
		if !rl.allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

func (rl *rateLimiter) middlewareAllMethods() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if !rl.allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

type wsCounter struct {
	max  int
	mu   sync.Mutex
	byIP map[string]int
}

func newWSCounter(max int) *wsCounter {
	return &wsCounter{max: max, byIP: make(map[string]int)}
}

func (wc *wsCounter) admit(key string) bool {
	if wc.max <= 0 {
		return true
	}
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if wc.byIP[key] >= wc.max {
		return false
	}
	wc.byIP[key]++
	return true
}

func (wc *wsCounter) release(key string) {
	if wc.max <= 0 {
		return
	}
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if wc.byIP[key] > 0 {
		wc.byIP[key]--
		if wc.byIP[key] == 0 {
			delete(wc.byIP, key)
		}
	}
}

func bodySizeLimit(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}
