package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	kfk "github.com/segmentio/kafka-go"
)

// keycloakEvent matches the JSON published by the Keycloak SPI Kafka listener.
type keycloakEvent struct {
	Type      string `json:"type"`
	Time      int64  `json:"time"` // epoch milliseconds
	UserID    string `json:"userId"`
	ClientID  string `json:"clientId"`
	Error     string `json:"error"`
	IPAddress string `json:"ipAddress"`
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	brokers := strings.Split(requireEnv(log, "KAFKA_BROKERS"), ",")
	authURL := requireEnv(log, "AUTH_SERVICE_URL")
	trustURL := requireEnv(log, "TRUST_SERVICE_URL")
	topic := env("KEYCLOAK_EVENTS_TOPIC", "keycloak.events")

	reader := kfk.NewReader(kfk.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		GroupID:        "keycloak-bridge",
		MaxBytes:       1 << 20,
		CommitInterval: time.Second,
		// Start from the earliest offset to process all existing events.
		// keycloak-bridge is idempotent: IncrFails/ResetFails are safe to re-apply.
		StartOffset: kfk.FirstOffset,
	})
	defer reader.Close()

	httpClient := &http.Client{Timeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("keycloak-bridge starting", "topic", topic, "mode", "kafka-spi")

	for {
		msg, err := reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Error("kafka read", "error", err)
			continue
		}

		var ev keycloakEvent
		if err := json.Unmarshal(msg.Value, &ev); err != nil {
			log.Warn("unmarshal keycloak event", "error", err)
			continue
		}

		if ev.UserID == "" {
			// LOGIN_ERROR for non-existent username — no user to attribute to.
			continue
		}

		userID, err := resolveUser(ctx, httpClient, authURL, ev.UserID)
		if err != nil {
			log.Warn("resolve user", "sub", ev.UserID, "error", err)
			continue
		}

		switch ev.Type {
		case "LOGIN_ERROR":
			if err := callTrust(ctx, httpClient, trustURL+"/trust/fails/incr", userID); err != nil {
				log.Error("incr fails", "user_id", userID, "error", err)
			} else {
				log.Info("LOGIN_ERROR: fails incremented",
					"user_id", userID, "kc_error", ev.Error, "ip", ev.IPAddress)
			}

		case "LOGIN":
			if err := callTrust(ctx, httpClient, trustURL+"/trust/fails/reset", userID); err != nil {
				log.Error("reset fails", "user_id", userID, "error", err)
			} else {
				log.Info("LOGIN: fails reset", "user_id", userID)
			}
		}
	}

	log.Info("keycloak-bridge stopped")
}

func resolveUser(ctx context.Context, c *http.Client, authURL, sub string) (string, error) {
	body, _ := json.Marshal(map[string]string{"sub": sub, "idp": "keycloak"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		authURL+"/auth/resolve-user", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth service: status %d", resp.StatusCode)
	}
	var result struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.UserID, nil
}

func callTrust(ctx context.Context, c *http.Client, endpoint, userID string) error {
	body, _ := json.Marshal(map[string]string{"user_id": userID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trust service: status %d", resp.StatusCode)
	}
	return nil
}

func requireEnv(log *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
