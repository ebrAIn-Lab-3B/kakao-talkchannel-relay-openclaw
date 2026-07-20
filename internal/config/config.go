package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/rs/zerolog/log"
)

var knownWeakSecrets = []string{
	"change-me", "dev-secret-change-me", "secret", "admin", "password",
}

type Config struct {
	Port                 int    `env:"PORT" envDefault:"8080"`
	DatabaseURL          string `env:"DATABASE_URL,required"`
	RedisURL             string `env:"REDIS_URL,required"`
	// KakaoSignatureSecret verifies an HMAC of the request body sent in
	// X-Kakao-Signature.
	//
	// Kakao 오픈빌더 cannot produce that: its skill-server header field attaches
	// a fixed string and nothing computes a per-request HMAC. Setting this for
	// an 오픈빌더 webhook makes every request fail with 401 Missing signature.
	// Use KakaoAPIKey instead; this stays for callers that can sign.
	KakaoSignatureSecret string `env:"KAKAO_SIGNATURE_SECRET"`
	// KakaoAPIKey is compared against the X-Api-Key header, which is what
	// 오픈빌더 can actually send.
	KakaoAPIKey string `env:"KAKAO_API_KEY"`
	AdminPasswordHash    string `env:"ADMIN_PASSWORD_HASH"`
	AdminSessionSecret   string `env:"ADMIN_SESSION_SECRET"`
	PortalSessionSecret  string `env:"PORTAL_SESSION_SECRET"`
	EncryptionKey        string `env:"ENCRYPTION_KEY"`
	QueueTTLSeconds      int    `env:"QUEUE_TTL_SECONDS" envDefault:"900"`
	CallbackTTLSeconds   int    `env:"CALLBACK_TTL_SECONDS" envDefault:"55"`
	LogLevel             string `env:"LOG_LEVEL" envDefault:"info"`
	PortalBaseURL        string `env:"PORTAL_BASE_URL" envDefault:""`
}

func (c *Config) QueueTTL() time.Duration {
	return time.Duration(c.QueueTTLSeconds) * time.Second
}

func (c *Config) CallbackTTL() time.Duration {
	return time.Duration(c.CallbackTTLSeconds) * time.Second
}

func (c *Config) Addr() string {
	return fmt.Sprintf(":%d", c.Port)
}

func (c *Config) Validate(isProduction bool) error {
	if c.AdminPasswordHash != "" {
		if !strings.HasPrefix(c.AdminPasswordHash, "$2a$") &&
			!strings.HasPrefix(c.AdminPasswordHash, "$2b$") &&
			!strings.HasPrefix(c.AdminPasswordHash, "$2y$") {
			return fmt.Errorf("ADMIN_PASSWORD_HASH must be a bcrypt hash (generate with: go run scripts/hash-password.go <password>)")
		}
	}

	if isProduction {
		if err := validateSecret("ADMIN_SESSION_SECRET", c.AdminSessionSecret); err != nil {
			return err
		}
		if err := validateSecret("PORTAL_SESSION_SECRET", c.PortalSessionSecret); err != nil {
			return err
		}

		if c.KakaoSignatureSecret == "" && c.KakaoAPIKey == "" {
			log.Warn().Msg("KAKAO_API_KEY and KAKAO_SIGNATURE_SECRET are both empty in production: the webhook accepts unauthenticated POSTs. Set KAKAO_API_KEY — 오픈빌더 cannot produce the HMAC that KAKAO_SIGNATURE_SECRET expects")
		}
		if c.KakaoSignatureSecret != "" {
			log.Warn().Msg("KAKAO_SIGNATURE_SECRET is set: every request must carry X-Kakao-Signature with an HMAC of the body. Kakao 오픈빌더 cannot generate that, so an 오픈빌더 webhook will fail with 401 — use KAKAO_API_KEY instead")
		}
		if strings.HasPrefix(c.RedisURL, "redis://") {
			log.Warn().Msg("REDIS_URL uses redis:// (not TLS) in production: consider using rediss://")
		}
		if c.EncryptionKey == "" {
			log.Warn().Msg("ENCRYPTION_KEY is empty in production: sensitive data will not be encrypted at rest")
		}
	}

	return nil
}

func validateSecret(name, value string) error {
	if len(value) < 32 {
		return fmt.Errorf("%s must be at least 32 characters in production (generate with: openssl rand -base64 32)", name)
	}
	for _, weak := range knownWeakSecrets {
		if value == weak {
			return fmt.Errorf("%s is a known weak default; set a strong secret in production", name)
		}
	}
	return nil
}

func Load() (*Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &cfg, nil
}
