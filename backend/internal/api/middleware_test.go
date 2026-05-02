package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestEngine(mw gin.HandlerFunc, method, path string) (*gin.Engine, *int32) {
	var hits int32
	r := gin.New()
	r.Use(mw)
	r.Handle(method, path, func(c *gin.Context) {
		atomic.AddInt32(&hits, 1)
		c.String(http.StatusOK, "ok")
	})
	return r, &hits
}

func newRequest(method, target string, body io.Reader) *http.Request {
	return httptest.NewRequest(method, target, body)
}

func TestWSCounter_Limits(t *testing.T) {
	c := newWSCounter(2)
	ok1, ok2 := c.admit("1.2.3.4"), c.admit("1.2.3.4")
	if !ok1 || !ok2 {
		t.Fatal("first two should be admitted")
	}
	if c.admit("1.2.3.4") {
		t.Fatal("third admission from same IP should be rejected")
	}
	if !c.admit("5.6.7.8") {
		t.Fatal("different IP should be admitted independently")
	}
	c.release("1.2.3.4")
	if !c.admit("1.2.3.4") {
		t.Fatal("after release, slot should be available")
	}
}

func TestWSCounter_ZeroDisabled(t *testing.T) {
	c := newWSCounter(0)
	for i := 0; i < 1000; i++ {
		if !c.admit("1.2.3.4") {
			t.Fatalf("zero limit should be unlimited; iteration %d", i)
		}
	}

	c.release("1.2.3.4")
}

func TestWSCounter_NegativeDisabled(t *testing.T) {
	c := newWSCounter(-5)
	ok1, ok2 := c.admit("a"), c.admit("a")
	if !ok1 || !ok2 {
		t.Fatal("negative limit should be unlimited")
	}
	c.release("a")
}

func TestWSCounter_ReleaseUnknownKey(t *testing.T) {
	c := newWSCounter(3)

	c.release("never-admitted")
	if !c.admit("never-admitted") {
		t.Fatal("key should admit normally after spurious release")
	}
}

func TestWSCounter_ReleaseDeletesWhenZero(t *testing.T) {
	c := newWSCounter(2)
	if !c.admit("solo") {
		t.Fatal("admit should succeed")
	}
	c.release("solo")

	c.mu.Lock()
	_, stillTracked := c.byIP["solo"]
	c.mu.Unlock()
	if stillTracked {
		t.Fatal("byIP entry should be deleted when counter drops to zero")
	}
	ok1, ok2 := c.admit("solo"), c.admit("solo")
	if !ok1 || !ok2 {
		t.Fatal("fresh tracking: should admit up to max again")
	}
	if c.admit("solo") {
		t.Fatal("after re-admitting to max, further admit must fail")
	}
}

func TestAuthBearerDynamic_NilProviderPasses(t *testing.T) {
	r, hits := newTestEngine(authBearerDynamic(nil), http.MethodGet, "/x")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, newRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestAuthBearerDynamic_EmptyTokenDisables(t *testing.T) {
	tp := NewTokenProvider("")
	r, hits := newTestEngine(authBearerDynamic(tp), http.MethodGet, "/x")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, newRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestAuthBearerDynamic_MissingHeader(t *testing.T) {
	tp := NewTokenProvider("secret")
	r, hits := newTestEngine(authBearerDynamic(tp), http.MethodGet, "/x")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, newRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "missing bearer token") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("handler should not be called")
	}
}

func TestAuthBearerDynamic_NoBearerPrefix(t *testing.T) {
	tp := NewTokenProvider("secret")
	r, hits := newTestEngine(authBearerDynamic(tp), http.MethodGet, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Basic aGVsbG86d29ybGQ=")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "missing bearer token") {
		t.Errorf("body=%s", w.Body.String())
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("handler should not be called")
	}
}

func TestAuthBearerDynamic_WrongToken(t *testing.T) {
	tp := NewTokenProvider("correct-horse-battery-staple")
	r, hits := newTestEngine(authBearerDynamic(tp), http.MethodGet, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer nope")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid bearer token") {
		t.Errorf("body=%s", w.Body.String())
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("handler should not be called")
	}
}

func TestAuthBearerDynamic_CorrectToken(t *testing.T) {
	tp := NewTokenProvider("correct-horse-battery-staple")
	r, hits := newTestEngine(authBearerDynamic(tp), http.MethodGet, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodGet, "/x", nil)

	req.Header.Set("Authorization", "Bearer   correct-horse-battery-staple   ")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestAuthBearerDynamic_RotationInvalidatesOldToken(t *testing.T) {
	tp := NewTokenProvider("old")
	r, hits := newTestEngine(authBearerDynamic(tp), http.MethodGet, "/x")

	w := httptest.NewRecorder()
	req := newRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer old")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first call with old token: status=%d", w.Code)
	}

	tp.Set("new")

	w = httptest.NewRecorder()
	req = newRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer old")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("rotated-out token should fail; status=%d", w.Code)
	}

	w = httptest.NewRecorder()
	req = newRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer new")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("new token should pass; status=%d body=%s", w.Code, w.Body.String())
	}

	if atomic.LoadInt32(hits) != 2 {
		t.Fatalf("expected 2 successful passes, got %d", atomic.LoadInt32(hits))
	}
}

func TestCSRF_SafeMethodsBypass(t *testing.T) {
	guard := csrfOriginGuard(nil)
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		r, hits := newTestEngine(guard, m, "/x")
		w := httptest.NewRecorder()
		req := newRequest(m, "/x", nil)

		req.Header.Set("Origin", "http://evil.example")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("method=%s status=%d body=%s", m, w.Code, w.Body.String())
		}
		if atomic.LoadInt32(hits) != 1 {
			t.Fatalf("method=%s handler not called", m)
		}
	}
}

func TestCSRF_POST_MatchingOriginHost(t *testing.T) {
	guard := csrfOriginGuard(nil)
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"
	req.Header.Set("Origin", "https://api.local")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestCSRF_POST_OriginInAllowlist(t *testing.T) {
	guard := csrfOriginGuard([]string{"https://trusted.example"})
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"
	req.Header.Set("Origin", "https://trusted.example")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestCSRF_POST_OriginMismatched(t *testing.T) {
	guard := csrfOriginGuard(nil)
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"
	req.Header.Set("Origin", "https://evil.example")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "cross-origin request blocked") {
		t.Errorf("body=%s", w.Body.String())
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("handler should not be called")
	}
}

func TestCSRF_POST_MalformedOrigin(t *testing.T) {
	guard := csrfOriginGuard(nil)
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"

	req.Header.Set("Origin", "http://bad\x7f")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid Origin") {
		t.Errorf("body=%s", w.Body.String())
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("handler should not be called")
	}
}

func TestCSRF_POST_NoOriginNoReferer(t *testing.T) {
	guard := csrfOriginGuard(nil)
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestCSRF_POST_RefererMatchingHost(t *testing.T) {
	guard := csrfOriginGuard(nil)
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"
	req.Header.Set("Referer", "https://api.local/some/page")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestCSRF_POST_RefererInAllowlist(t *testing.T) {

	guard := csrfOriginGuard([]string{"https://trusted.example/ui"})
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"
	req.Header.Set("Referer", "https://trusted.example/ui")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("handler not called")
	}
}

func TestCSRF_POST_RefererMismatchNotAllowlisted(t *testing.T) {
	guard := csrfOriginGuard(nil)
	r, hits := newTestEngine(guard, http.MethodPost, "/x")
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Host = "api.local"
	req.Header.Set("Referer", "https://evil.example/login")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "cross-origin request blocked") {
		t.Errorf("body=%s", w.Body.String())
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("handler should not be called")
	}
}

func TestRateLimiter_IndependentBuckets(t *testing.T) {
	rl := newRateLimiter(0.0001, 1)
	if !rl.allow("a") {
		t.Fatal("bucket a first request should pass")
	}
	if rl.allow("a") {
		t.Fatal("bucket a second request should be denied")
	}
	if !rl.allow("b") {
		t.Fatal("bucket b must have independent burst")
	}
}

func TestRateLimiter_BurstExhaustion(t *testing.T) {
	rl := newRateLimiter(0.0001, 3)
	for i := 0; i < 3; i++ {
		if !rl.allow("k") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if rl.allow("k") {
		t.Fatal("4th request should be denied after burst exhaustion")
	}
}

func TestRateLimiter_ConcurrentDistinctKeysSurvive(t *testing.T) {
	rl := newRateLimiter(1000, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := string(rune('a' + id%26))
			for j := 0; j < 20; j++ {
				_ = rl.allow(key)
			}
		}(i)
	}
	wg.Wait()

	for c := 'a'; c <= 'z'; c++ {
		if !rl.allow(string(c)) {
			t.Errorf("bucket %q should admit after concurrent burst", string(c))
		}
	}
}

func TestRateLimiter_Middleware_BypassesSafeMethods(t *testing.T) {
	rl := newRateLimiter(0.0001, 1)

	if !rl.allow("127.0.0.1") {
		t.Fatal("precondition")
	}

	r := gin.New()
	r.Use(rl.middleware())
	var hits int32
	r.GET("/x", func(c *gin.Context) {
		atomic.AddInt32(&hits, 1)
		c.String(http.StatusOK, "ok")
	})

	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {

		r.Handle(m, "/y", func(c *gin.Context) {
			atomic.AddInt32(&hits, 1)
			c.String(http.StatusOK, "ok")
		})
	}

	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		w := httptest.NewRecorder()
		req := newRequest(m, "/y", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("method=%s should bypass; status=%d", m, w.Code)
		}
	}
}

func TestRateLimiter_Middleware_UsesAuthHeaderKey(t *testing.T) {
	rl := newRateLimiter(0.0001, 1)
	r := gin.New()
	r.Use(rl.middleware())
	var hits int32
	r.POST("/x", func(c *gin.Context) {
		atomic.AddInt32(&hits, 1)
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Authorization", "Bearer alice")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("alice first: status=%d", w.Code)
	}

	w = httptest.NewRecorder()
	req = newRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Authorization", "Bearer alice")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("alice second: status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "rate limit exceeded") {
		t.Errorf("body=%s", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = newRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Authorization", "Bearer bob")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bob first: status=%d", w.Code)
	}

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("handler hits=%d, want 2", got)
	}
}

func TestRateLimiter_Middleware_FallsBackToClientIP(t *testing.T) {
	rl := newRateLimiter(0.0001, 1)
	r := gin.New()
	r.Use(rl.middleware())
	r.POST("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", nil)

	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first: status=%d", w.Code)
	}

	w = httptest.NewRecorder()
	req = newRequest(http.MethodPost, "/x", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second should be rate-limited (same ClientIP); status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestRateLimiter_MiddlewareAllMethods_LimitsGET(t *testing.T) {
	rl := newRateLimiter(0.0001, 1)
	r := gin.New()
	r.Use(rl.middlewareAllMethods())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, newRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("first GET: status=%d", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, newRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second GET should be limited; status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "rate limit exceeded") {
		t.Errorf("body=%s", w.Body.String())
	}
}

func TestBodySizeLimit_UnderMaxPasses(t *testing.T) {
	r := gin.New()
	r.Use(bodySizeLimit(1024))
	var seenBytes int
	r.POST("/x", func(c *gin.Context) {
		data, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusInternalServerError, "read error: %v", err)
			return
		}
		seenBytes = len(data)
		c.String(http.StatusOK, "ok")
	})

	payload := bytes.Repeat([]byte("a"), 100)
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if seenBytes != 100 {
		t.Errorf("seen %d bytes, want 100", seenBytes)
	}
}

func TestBodySizeLimit_OverMaxErrors(t *testing.T) {
	r := gin.New()
	r.Use(bodySizeLimit(16))
	var readErr error
	r.POST("/x", func(c *gin.Context) {
		_, readErr = io.ReadAll(c.Request.Body)
		if readErr != nil {
			c.String(http.StatusRequestEntityTooLarge, "too big")
			return
		}
		c.String(http.StatusOK, "ok")
	})

	payload := bytes.Repeat([]byte("a"), 1024)
	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/x", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	r.ServeHTTP(w, req)

	if readErr == nil {
		t.Fatalf("expected read error for oversize body, got nil (status=%d body=%s)", w.Code, w.Body.String())
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
