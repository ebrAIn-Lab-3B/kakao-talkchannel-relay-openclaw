package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/openclaw/relay-server-go/internal/middleware"
	"github.com/openclaw/relay-server-go/internal/service"
	"github.com/openclaw/relay-server-go/internal/sse"
)

type EventsHandler struct {
	broker         *sse.Broker
	messageService *service.MessageService
}

func NewEventsHandler(broker *sse.Broker, messageService *service.MessageService) *EventsHandler {
	return &EventsHandler{
		broker:         broker,
		messageService: messageService,
	}
}

func (h *EventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	account := middleware.GetAccount(r.Context())
	session := middleware.GetSession(r.Context())

	// Determine subscription ID
	var subscribeID string
	var accountID string

	if account != nil {
		// Paired session or legacy account token
		subscribeID = account.ID
		accountID = account.ID
	} else if session != nil {
		// Pending session - subscribe by session ID for pairing events
		subscribeID = "session:" + session.ID
		accountID = ""
	} else {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	client := h.broker.Subscribe(subscribeID)
	defer h.broker.Unsubscribe(client)

	log.Info().
		Str("subscribeId", subscribeID).
		Str("accountId", accountID).
		Msg("sse connection established")

	ctx := r.Context()

	// Send queued messages only if we have an account
	if accountID != "" {
		if err := h.sendQueuedMessages(ctx, w, flusher, accountID); err != nil {
			log.Error().Err(err).Msg("failed to send queued messages")
		}
	}

	h.sendEvent(w, flusher, "connected", map[string]any{
		"accountId": accountID,
		"sessionId": func() string {
			if session != nil {
				return session.ID
			}
			return ""
		}(),
		"status": func() string {
			if session != nil {
				return string(session.Status)
			}
			return "paired"
		}(),
	})

	heartbeat := time.NewTicker(sse.HeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().
				Str("subscribeId", subscribeID).
				Msg("sse connection closed by client")
			return

		case <-client.Done:
			log.Info().
				Str("subscribeId", subscribeID).
				Msg("sse connection closed by broker")
			return

		case event := <-client.Events:
			if err := h.sendRawEvent(w, flusher, event); err != nil {
				log.Error().Err(err).Msg("failed to send event")
				return
			}
			// Live-pushed messages must be marked delivered here as well.
			// Otherwise they stay `queued` until the next reconnect flush and
			// the cleanup job marks them `expired` — even though the reply was
			// already delivered — which makes the message table misreport
			// failures. sendQueuedMessages does the same for the flush path.
			if event.Type == "message" {
				h.markEventDelivered(ctx, event)
			}

		case <-heartbeat.C:
			if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
				log.Debug().
					Str("subscribeId", subscribeID).
					Msg("heartbeat failed, closing connection")
				return
			}
			flusher.Flush()
		}
	}
}

// markEventDelivered marks a live-pushed inbound message as delivered. The
// message id travels inside the SSE payload (see InboundMessage.ToSSEEventData),
// so it has to be read back out of the raw event data.
func (h *EventsHandler) markEventDelivered(ctx context.Context, event sse.Event) {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		log.Warn().Err(err).Msg("failed to decode sse message event for delivery marking")
		return
	}
	if payload.ID == "" {
		log.Warn().Msg("sse message event has no id; skipping delivery marking")
		return
	}
	if err := h.messageService.MarkDelivered(ctx, payload.ID); err != nil {
		log.Warn().Err(err).Str("messageId", payload.ID).Msg("failed to mark message as delivered")
	}
}

func (h *EventsHandler) sendQueuedMessages(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, accountID string) error {
	messages, err := h.messageService.FindQueuedByAccountID(ctx, accountID)
	if err != nil {
		return err
	}

	for _, msg := range messages {
		sseData := msg.ToSSEEventData()
		log.Debug().
			Str("messageId", msg.ID).
			RawJSON("sseEventData", sseData).
			Msg("sending queued sse message event")

		event := sse.Event{
			Type: "message",
			Data: sseData,
		}

		if err := h.sendRawEvent(w, flusher, event); err != nil {
			return err
		}

		if err := h.messageService.MarkDelivered(ctx, msg.ID); err != nil {
			log.Warn().Err(err).Str("messageId", msg.ID).Msg("failed to mark message as delivered")
		}
	}

	if len(messages) > 0 {
		log.Info().
			Str("accountId", accountID).
			Int("count", len(messages)).
			Msg("sent queued messages")
	}

	return nil
}

func (h *EventsHandler) sendEvent(w http.ResponseWriter, flusher http.Flusher, eventType string, data any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return h.sendRawEvent(w, flusher, sse.Event{Type: eventType, Data: jsonData})
}

func (h *EventsHandler) sendRawEvent(w http.ResponseWriter, flusher http.Flusher, event sse.Event) error {
	if _, err := fmt.Fprintf(w, "event: %s\n", event.Type); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", event.Data); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}
