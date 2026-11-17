package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeaders())
	r.GET("/api/x", func(c *gin.Context) { c.Status(200) })
	r.GET("/static/x.js", func(c *gin.Context) { c.Status(200) })

	for _, path := range []string{"/api/x", "/static/x.js"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		for _, h := range []string{"Content-Security-Policy", "Referrer-Policy", "Permissions-Policy", "X-Frame-Options", "Strict-Transport-Security"} {
			if w.Header().Get(h) == "" {
				t.Errorf("%s: missing %s", path, h)
			}
		}
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/x", nil))
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("API Cache-Control = %q, want no-store", got)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/static/x.js", nil))
	if got := w.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("static Cache-Control = %q, want no-cache", got)
	}
}

func TestLimitBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(LimitBody(64))
	r.POST("/", func(c *gin.Context) {
		var v map[string]any
		if err := c.ShouldBindJSON(&v); err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.Status(http.StatusOK)
	})

	small := httptest.NewRecorder()
	r.ServeHTTP(small, httptest.NewRequest("POST", "/", strings.NewReader(`{"a":"b"}`)))
	if small.Code != http.StatusOK {
		t.Errorf("small body: got %d, want 200", small.Code)
	}

	big := httptest.NewRecorder()
	r.ServeHTTP(big, httptest.NewRequest("POST", "/", strings.NewReader(`{"a":"`+strings.Repeat("x", 1000)+`"}`)))
	if big.Code != http.StatusBadRequest {
		t.Errorf("oversized body: got %d, want 400", big.Code)
	}
}

func TestAccessLogOmitsQueryString(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	r := gin.New()
	r.Use(AccessLog())
	r.GET("/api/auth/oidc/callback", func(c *gin.Context) { c.Status(200) })
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/auth/oidc/callback?code=SECRETCODE&state=SECRETSTATE", nil))

	out := buf.String()
	if strings.Contains(out, "SECRETCODE") || strings.Contains(out, "SECRETSTATE") {
		t.Errorf("access log leaked query string: %s", out)
	}
	if !strings.Contains(out, "/api/auth/oidc/callback") {
		t.Errorf("access log missing path: %s", out)
	}
}
