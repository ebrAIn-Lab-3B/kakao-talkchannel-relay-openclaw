package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/openclaw/relay-server-go/internal/util"
)

const KakaoBodyContextKey contextKey = "kakaoBody"

func GetKakaoBody(ctx context.Context) any {
	return ctx.Value(KakaoBodyContextKey)
}

// KakaoSignatureMiddleware authenticates inbound Kakao webhooks.
//
// Two mechanisms, because the platform constrains the choice:
//
//   - apiKey compares the X-Api-Key header against a fixed value. This is what
//     Kakao 오픈빌더 can send — its skill-server header field attaches a static
//     string.
//   - secret verifies HMAC-SHA256(body) in X-Kakao-Signature. Stronger, since it
//     binds the signature to the body, but 오픈빌더 has no way to compute it.
//     Kept for callers that can sign.
//
// A fixed key is weaker than an HMAC: it does not bind to the request body and
// gives no replay protection. It still closes the hole this replaces, which was
// accepting any POST from anyone who learned the URL. It is only meaningful
// over TLS.
//
// With neither configured, requests pass through and a warning is logged —
// deliberately, so an unconfigured deployment keeps working rather than
// silently dropping every message.
type KakaoSignatureMiddleware struct {
	secret string
	apiKey string
}

func NewKakaoSignatureMiddleware(secret string) *KakaoSignatureMiddleware {
	return &KakaoSignatureMiddleware{secret: secret}
}

// NewKakaoAuthMiddleware accepts either mechanism. Both may be set, in which
// case a request satisfying either one is allowed.
func NewKakaoAuthMiddleware(secret, apiKey string) *KakaoSignatureMiddleware {
	return &KakaoSignatureMiddleware{secret: secret, apiKey: apiKey}
}

func (m *KakaoSignatureMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.secret == "" && m.apiKey == "" {
			log.Warn().Msg("kakao webhook auth bypassed: neither KAKAO_API_KEY nor KAKAO_SIGNATURE_SECRET is configured")
			next.ServeHTTP(w, r)
			return
		}

		if m.apiKey != "" {
			presented := r.Header.Get("X-Api-Key")
			if presented == "" {
				log.Warn().Msg("kakao webhook auth: missing X-Api-Key header")
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "Missing API key",
				})
				return
			}
			if !util.ConstantTimeEqual(presented, m.apiKey) {
				log.Warn().Msg("kakao webhook auth: invalid X-Api-Key")
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "Invalid API key",
				})
				return
			}
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error().Err(err).Msg("kakao webhook auth: failed to read body")
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Failed to read request body",
			})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		if m.secret != "" {
			signature := r.Header.Get("X-Kakao-Signature")
			if signature == "" {
				log.Warn().Msg("kakao webhook auth: missing signature header")
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "Missing signature",
				})
				return
			}

			computed := util.HmacSHA256(m.secret, string(body))
			if !util.ConstantTimeEqual(computed, signature) {
				log.Warn().Msg("kakao webhook auth: invalid signature")
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "Invalid signature",
				})
				return
			}
		}

		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			log.Error().Err(err).Msg("kakao signature middleware: failed to parse body")
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid JSON body",
			})
			return
		}

		ctx := context.WithValue(r.Context(), KakaoBodyContextKey, parsed)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
