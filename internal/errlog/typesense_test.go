package errlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testDBError struct{}

func (testDBError) Error() string    { return "private-email@example.test database password" }
func (testDBError) SQLState() string { return "23505" }

func TestTypesenseSharedLogContract(t *testing.T) {
	received := make(chan event, 8)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/collections/application_logs_v1/documents" {
			t.Errorf("unexpected Typesense request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-TYPESENSE-API-KEY") != "write-key" {
			t.Error("missing write key")
		}
		var e event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			t.Errorf("decode event: %v", err)
		}
		received <- e
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	var output bytes.Buffer
	local := slog.New(slog.NewJSONHandler(&output, nil))
	sink, err := NewTypesenseSink(ts.URL, "write-key", local)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(NewHandler(&output, "test", sink))
	ctx := WithRequest(context.Background(), "request-123", http.MethodPost, func() string { return "/api/auth/login" })
	logger.Info("dev-only mail", "body", "local-only-value")
	logger.InfoContext(ctx, "login succeeded", "event", "login_succeeded", "status", http.StatusOK)
	logger.WarnContext(ctx, "login rejected", "event", "login_failed", "status", http.StatusUnauthorized,
		"response_code", "invalid_credentials", "response_message", "Invalid username or password.")
	logger.ErrorContext(ctx, "login failed to save session", "status", http.StatusInternalServerError,
		"err", fmt.Errorf("sensitive wrapper: %w", testDBError{}), "password", "sensitive-field")
	logger.Log(ctx, LevelCritical, "critical level test")

	deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sink.Close(deadline)
	if len(received) != 4 {
		t.Fatalf("received %d documents, want 4", len(received))
	}
	for _, level := range []string{"info", "warning", "error", "critical"} {
		e := <-received
		if e.Level != level || e.Service != "authserver-go" || e.Environment != "test" ||
			e.RequestID != "request-123" || e.HTTPMethod != http.MethodPost || e.HTTPRoute != "/api/auth/login" ||
			e.Timestamp <= 0 || e.Source == "" {
			t.Errorf("unexpected %s event: %+v", level, e)
		}
		if level == "warning" && (e.ResponseCode != "invalid_credentials" || e.ResponseMessage == "") {
			t.Errorf("missing login response metadata: %+v", e)
		}
		if level == "error" && (e.ErrorCode != "sqlstate_23505" || e.HTTPStatus != 500) {
			t.Errorf("missing database metadata: %+v", e)
		}
	}
	for _, secret := range []string{"private-email@example.test", "database password", "sensitive wrapper", "sensitive-field", "write-key"} {
		if strings.Contains(output.String(), secret) {
			t.Errorf("log contained raw data %q", secret)
		}
	}
}

func TestTypesenseFailureKeepsLocalEvent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private Typesense response", http.StatusUnauthorized)
	}))
	defer ts.Close()

	var output, delivery bytes.Buffer
	sink, err := NewTypesenseSink(ts.URL, "write-key", slog.New(slog.NewJSONHandler(&delivery, nil)))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(NewHandler(&output, "test", sink))
	logger.Error("failed to save login")
	deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sink.Close(deadline)
	if !strings.Contains(output.String(), "failed to save login") ||
		!strings.Contains(delivery.String(), "Typesense returned HTTP 401") ||
		strings.Contains(delivery.String(), "private Typesense response") {
		t.Fatalf("unexpected local logs: %s %s", output.String(), delivery.String())
	}
}

func TestTypesenseProvisionsMissingCollection(t *testing.T) {
	for _, tc := range []struct {
		name         string
		createStatus int
		wantError    string
	}{
		{name: "created", createStatus: http.StatusCreated},
		{name: "already created by another writer", createStatus: http.StatusConflict},
		{name: "missing create permission", createStatus: http.StatusUnauthorized, wantError: "check collections:create permission"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const documentsPath = "/proxy/collections/application_logs_v1/documents"
			const collectionsPath = "/proxy/collections"
			const document = `{"message":"first log"}`
			requests := make(chan string, 4)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				firstRequest := len(requests) == 0
				requests <- r.URL.Path
				if r.Method != http.MethodPost || r.Header.Get("X-TYPESENSE-API-KEY") != "log-key" {
					t.Errorf("unexpected method or missing log key for %s", r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.URL.Path {
				case documentsPath:
					if string(body) != document {
						t.Errorf("unexpected log document: %s", body)
					}
					if firstRequest {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.WriteHeader(http.StatusCreated)
				case collectionsPath:
					var schema struct {
						Name   string            `json:"name"`
						Fields []json.RawMessage `json:"fields"`
					}
					if err := json.Unmarshal(body, &schema); err != nil || schema.Name != collection || len(schema.Fields) == 0 {
						t.Errorf("invalid collection schema: %s (%v)", body, err)
					}
					w.WriteHeader(tc.createStatus)
				default:
					t.Errorf("unexpected request path %q", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer ts.Close()

			sink, err := NewTypesenseSink(ts.URL+"/proxy/", "log-key", slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			defer sink.Close(ctx)

			err = sink.send(ctx, []byte(document))
			wantPaths := []string{documentsPath, collectionsPath}
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				wantPaths = append(wantPaths, documentsPath)
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("send error = %v, want %q", err, tc.wantError)
			}
			if len(requests) != len(wantPaths) {
				t.Fatalf("got %d requests, want %d", len(requests), len(wantPaths))
			}
			for _, want := range wantPaths {
				if got := <-requests; got != want {
					t.Errorf("request path = %q, want %q", got, want)
				}
			}
		})
	}
}
