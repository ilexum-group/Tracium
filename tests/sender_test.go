package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ilexum-group/tracium/internal/config"
	"github.com/ilexum-group/tracium/internal/sender"
	"github.com/ilexum-group/tracium/pkg/models"
)

func TestSendDataSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer testtoken" {
			t.Errorf("Missing or incorrect Authorization header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{ServerURL: server.URL, AgentToken: "testtoken"}
	data := models.SystemData{Timestamp: 1}
	if err := sender.SendData(cfg, data); err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
}

func TestSendDataServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &config.Config{ServerURL: server.URL, AgentToken: "testtoken"}
	data := models.SystemData{Timestamp: 1}
	if err := sender.SendData(cfg, data); err == nil {
		t.Error("Expected error for server status, got nil")
	}
}

func TestSendDataInvalidURL(t *testing.T) {
	cfg := &config.Config{ServerURL: "http://invalid:url:123/bad", AgentToken: "testtoken"}
	data := models.SystemData{Timestamp: 1}
	if err := sender.SendData(cfg, data); err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}
