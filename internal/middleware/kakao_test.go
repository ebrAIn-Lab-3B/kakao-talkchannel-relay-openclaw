package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openclaw/relay-server-go/internal/util"
)

func TestKakaoSignatureMiddleware(t *testing.T) {
	secret := "test-secret"
	body := `{"key":"value"}`
	validSignature := util.HmacSHA256(secret, body)

	t.Run("passes through when secret is empty", func(t *testing.T) {
		middleware := NewKakaoSignatureMiddleware("")
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("rejects request without signature header", func(t *testing.T) {
		middleware := NewKakaoSignatureMiddleware(secret)
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}))

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects request with invalid signature", func(t *testing.T) {
		middleware := NewKakaoSignatureMiddleware(secret)
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}))

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Kakao-Signature", "invalid-signature")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("allows request with valid signature", func(t *testing.T) {
		middleware := NewKakaoSignatureMiddleware(secret)
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Kakao-Signature", validSignature)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("stores parsed body in context", func(t *testing.T) {
		middleware := NewKakaoSignatureMiddleware(secret)
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parsed := GetKakaoBody(r.Context())
			assert.NotNil(t, parsed)

			m, ok := parsed.(map[string]any)
			assert.True(t, ok)
			assert.Equal(t, "value", m["key"])
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Kakao-Signature", validSignature)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		invalidBody := `{invalid json}`
		invalidSignature := util.HmacSHA256(secret, invalidBody)

		middleware := NewKakaoSignatureMiddleware(secret)
		handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}))

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(invalidBody))
		req.Header.Set("X-Kakao-Signature", invalidSignature)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// Kakao 오픈빌더 cannot compute a per-request HMAC — its skill-server header
// field attaches a fixed string. Authenticating an 오픈빌더 webhook therefore
// has to compare a static key, which is what these cover.
func TestKakaoAPIKeyAuth(t *testing.T) {
	const apiKey = "test-api-key"
	const body = `{"key":"value"}`

	newHandler := func(m *KakaoSignatureMiddleware, called *bool) http.Handler {
		return m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*called = true
			w.WriteHeader(http.StatusOK)
		}))
	}

	t.Run("passes through when neither mechanism is configured", func(t *testing.T) {
		called := false
		handler := newHandler(NewKakaoAuthMiddleware("", ""), &called)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// An unconfigured deployment keeps working rather than dropping
		// every message.
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
	})

	t.Run("accepts a matching X-Api-Key", func(t *testing.T) {
		called := false
		handler := newHandler(NewKakaoAuthMiddleware("", apiKey), &called)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Api-Key", apiKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
	})

	t.Run("rejects a missing X-Api-Key", func(t *testing.T) {
		called := false
		handler := newHandler(NewKakaoAuthMiddleware("", apiKey), &called)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called)
	})

	t.Run("rejects a wrong X-Api-Key", func(t *testing.T) {
		called := false
		handler := newHandler(NewKakaoAuthMiddleware("", apiKey), &called)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Api-Key", "wrong")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called)
	})

	t.Run("body is still readable downstream", func(t *testing.T) {
		var seen []byte
		m := NewKakaoAuthMiddleware("", apiKey)
		handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Api-Key", apiKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, body, string(seen))
	})

	t.Run("an api key alone does not require a signature", func(t *testing.T) {
		// The 오픈빌더 case: a static header and no HMAC anywhere.
		called := false
		handler := newHandler(NewKakaoAuthMiddleware("", apiKey), &called)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Api-Key", apiKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
	})

	t.Run("both configured requires both", func(t *testing.T) {
		called := false
		handler := newHandler(NewKakaoAuthMiddleware("sig-secret", apiKey), &called)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(body))
		req.Header.Set("X-Api-Key", apiKey)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// The key passed but the signature is absent.
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called)
	})
}
