package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/openclaw/relay-server-go/internal/config"
	"github.com/openclaw/relay-server-go/internal/database"
	"github.com/openclaw/relay-server-go/internal/handler"
	"github.com/openclaw/relay-server-go/internal/jobs"
	"github.com/openclaw/relay-server-go/internal/middleware"
	"github.com/openclaw/relay-server-go/internal/redis"
	"github.com/openclaw/relay-server-go/internal/repository"
	"github.com/openclaw/relay-server-go/internal/service"
	"github.com/openclaw/relay-server-go/internal/sse"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	setLogLevel(cfg.LogLevel)

	isProduction := os.Getenv("K_SERVICE") != "" || os.Getenv("FLY_APP_NAME") != ""
	if err := cfg.Validate(isProduction); err != nil {
		log.Fatal().Err(err).Msg("invalid configuration")
	}

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), config.DBPingTimeout)
	if err := db.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("failed to ping database")
	}
	cancel()
	log.Info().Msg("database connected")

	redisClient, err := redis.NewClient(cfg.RedisURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to redis")
	}
	defer redisClient.Close()
	log.Info().Msg("redis connected")

	accountRepo := repository.NewAccountRepository(db.DB)
	convRepo := repository.NewConversationRepository(db.DB)
	pairingCodeRepo := repository.NewPairingCodeRepository(db.DB)
	portalAccessCodeRepo := repository.NewPortalAccessCodeRepository(db.DB)
	portalUserRepo := repository.NewPortalUserRepository(db.DB)
	portalSessionRepo := repository.NewPortalSessionRepository(db.DB)
	adminSessionRepo := repository.NewAdminSessionRepository(db.DB)
	inboundMsgRepo := repository.NewInboundMessageRepository(db.DB)
	outboundMsgRepo := repository.NewOutboundMessageRepository(db.DB)
	sessionRepo := repository.NewSessionRepository(db.DB)

	broker := sse.NewBroker(redisClient)
	defer broker.Close()

	convService := service.NewConversationService(convRepo)
	pairingService := service.NewPairingService(pairingCodeRepo, convRepo)
	portalAccessService := service.NewPortalAccessService(portalAccessCodeRepo, convRepo, redisClient)
	messageService := service.NewMessageService(inboundMsgRepo, outboundMsgRepo)
	kakaoService := service.NewKakaoService()
	adminService := service.NewAdminService(
		db.DB, adminSessionRepo, accountRepo, convRepo,
		inboundMsgRepo, outboundMsgRepo, portalUserRepo, sessionRepo,
		cfg.AdminPasswordHash, cfg.AdminSessionSecret,
	)
	portalService := service.NewPortalService(
		portalUserRepo, portalSessionRepo, accountRepo,
		cfg.PortalSessionSecret,
	)
	sessionService := service.NewSessionService(db, sessionRepo, accountRepo, broker)
	ipRateLimiter := service.NewRateLimiter(redisClient.Client)

	authMiddleware := middleware.NewAuthMiddleware(accountRepo, sessionRepo)
	rateLimitMiddleware := middleware.NewRedisRateLimitMiddleware(redisClient.Client)
	adminSessionMiddleware := middleware.NewAdminSessionMiddleware(
		adminSessionRepo, cfg.AdminPasswordHash, cfg.AdminSessionSecret,
	)
	kakaoSignatureMiddleware := middleware.NewKakaoAuthMiddleware(cfg.KakaoSignatureSecret, cfg.KakaoAPIKey)
	portalSessionMiddleware := middleware.NewPortalSessionMiddleware(
		portalSessionRepo, portalUserRepo, cfg.PortalSessionSecret,
	)
	sessionCreateRateLimit := middleware.NewIPRateLimitMiddleware(ipRateLimiter, 10, 5*time.Minute, "session_create")
	sessionStatusRateLimit := middleware.NewIPRateLimitMiddleware(ipRateLimiter, 30, 1*time.Minute, "session_status")

	csrfMiddleware := middleware.NewCSRFMiddleware(isProduction)
	bodyLimitMiddleware := middleware.NewBodyLimitMiddleware(0)
	securityHeadersMiddleware := middleware.NewSecurityHeadersMiddleware(isProduction)

	kakaoHandler := handler.NewKakaoHandler(
		convService, sessionService, messageService, portalAccessService, broker, cfg.CallbackTTL(), cfg.PortalBaseURL,
	)
	eventsHandler := handler.NewEventsHandler(broker, messageService)
	openclawHandler := handler.NewOpenClawHandler(messageService, kakaoService)
	adminHandler := handler.NewAdminHandler(adminService, adminSessionMiddleware.Handler, isProduction)
	portalHandler := handler.NewPortalHandler(
		portalService, pairingService, portalAccessService, convService, messageService, adminService, isProduction,
	)
	sessionHandler := handler.NewSessionHandler(sessionService)

	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.RequestLogger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(config.ServerRequestTimeout))
	r.Use(bodyLimitMiddleware.Handler)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":    "ok",
			"timestamp": time.Now().UnixMilli(),
		})
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/portal/", http.StatusFound)
	})

	r.Route("/kakao-talkchannel", func(r chi.Router) {
		r.Use(kakaoSignatureMiddleware.Handler)
		r.Post("/webhook", kakaoHandler.Webhook)
	})

	r.Route("/v1", func(r chi.Router) {
		r.Use(authMiddleware.Handler)
		r.Use(rateLimitMiddleware.Handler)
		r.Get("/events", eventsHandler.ServeHTTP)
	})

	r.Route("/openclaw", func(r chi.Router) {
		r.Use(authMiddleware.Handler)
		r.Use(rateLimitMiddleware.Handler)
		r.Mount("/", openclawHandler.Routes())
	})

	r.Route("/v1/sessions", func(r chi.Router) {
		r.With(sessionCreateRateLimit.Handler).Post("/create", sessionHandler.CreateSession)
		r.With(sessionStatusRateLimit.Handler).Get("/{sessionToken}/status", sessionHandler.GetSessionStatus)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Use(securityHeadersMiddleware.Handler)
		r.Use(csrfMiddleware.Handler)
		r.Mount("/", adminHandler.Routes())
		r.NotFound(handler.StaticFileServer("static/admin", "/admin").ServeHTTP)
	})

	r.Route("/portal", func(r chi.Router) {
		r.Use(securityHeadersMiddleware.Handler)
		r.Use(csrfMiddleware.Handler)

		// API Routes
		r.Route("/api", func(r chi.Router) {
			// Public API
			r.Get("/stats/public", portalHandler.GetPublicStats)
			r.Post("/auth/code", portalHandler.LoginWithCode)
			r.Get("/code/stats", portalHandler.GetCodeStats)
			r.Get("/code/messages", portalHandler.GetCodeMessages)

			// Authenticated API
			r.Group(func(r chi.Router) {
				r.Use(portalSessionMiddleware.Handler)
				r.Post("/logout", portalHandler.Logout)
				r.Get("/me", portalHandler.Me)
				r.Get("/stats", portalHandler.GetStats)
				r.Post("/pairing/generate", portalHandler.GeneratePairingCode)
				r.Get("/connections", portalHandler.ListConnections)
				r.Post("/connections/{conversationKey}/unpair", portalHandler.UnpairConnection)
				r.Patch("/connections/{conversationKey}/block", portalHandler.BlockConnection)
				r.Get("/token", portalHandler.GetToken)
				r.Post("/token/regenerate", portalHandler.RegenerateToken)
				r.Delete("/account", portalHandler.DeleteAccount)
				r.Get("/messages", portalHandler.GetMessages)
			})
		})

		r.NotFound(handler.StaticFileServer("static/portal", "/portal").ServeHTTP)
	})

	cleanupJob := jobs.NewCleanupJob(
		adminSessionRepo, portalSessionRepo, portalAccessCodeRepo, pairingCodeRepo, inboundMsgRepo,
		sessionRepo, config.CleanupJobInterval,
	)
	cleanupJob.Start()
	defer cleanupJob.Stop()

	server := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      r,
		ReadTimeout:  config.ServerReadTimeout,
		WriteTimeout: 0,
		IdleTimeout:  config.ServerIdleTimeout,
	}

	go func() {
		log.Info().Str("addr", cfg.Addr()).Msg("starting server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutting down server")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ServerShutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("server forced to shutdown")
	}

	log.Info().Msg("server stopped")
}

func setLogLevel(level string) {
	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
