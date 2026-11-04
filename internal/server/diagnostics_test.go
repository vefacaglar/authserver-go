package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/errlog"
	"go-authserver/internal/oidc"
	"go-authserver/internal/store"
	"go-authserver/internal/store/memory"
)

func TestDiagnosticsLoginFailures(t *testing.T) {
	for _, tc := range []struct {
		name, responseCode, errorCode string
		status                        int
		csrf, rateLimit               bool
		err                           error
	}{
		{name: "csrf", responseCode: "antiforgery_failed", errorCode: "antiforgery_failed", status: 403},
		{name: "invalid credentials", responseCode: "invalid_credentials", errorCode: "invalid_credentials", status: 401, csrf: true},
		{name: "server failure", responseCode: "server_error", errorCode: "deadline_exceeded", status: 500, csrf: true,
			err: fmt.Errorf("sensitive-store-error: %w", context.DeadlineExceeded)},
		{name: "rate limit", responseCode: "too_many_requests", errorCode: "rate_limited", status: 429, rateLimit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(errlog.NewHandler(&output, "test", nil))
			clk := clock.NewFakeClock(time.Unix(0, 0))
			router := NewRouter(RouterConfig{LoginRateLimitRPS: 1, LoginRateBurst: 1}, RouterOptions{Logger: logger},
				Handlers{Login: &oidc.LoginHandler{
					Users:   diagnosticUsers{err: tc.err},
					Tracker: memory.NewLoginAttemptTracker(clk.Now),
					Clock:   clk,
					Logger:  logger,
				}})

			if tc.rateLimit {
				router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/auth/login", nil))
				output.Reset()
			}
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login?secret=private-query",
				strings.NewReader(`{"username":"private-username","password":"private-password"}`))
			req.Header.Set("X-Request-Id", "private-client-id")
			if tc.csrf {
				rr := httptest.NewRecorder()
				token, err := oidc.APICSRFGuard(false).Issue(rr)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-CSRF-Token", token)
				for _, cookie := range rr.Result().Cookies() {
					req.AddCookie(cookie)
				}
			}
			res := httptest.NewRecorder()
			router.ServeHTTP(res, req)
			if res.Code != tc.status {
				t.Fatalf("HTTP status = %d, want %d", res.Code, tc.status)
			}
			for _, secret := range []string{"private-", "sensitive-store-error"} {
				if strings.Contains(output.String(), secret) {
					t.Fatalf("request or error data leaked: %s", output.String())
				}
			}
			var e struct {
				Event        string `json:"event"`
				Level        string `json:"level"`
				RequestID    string `json:"request_id"`
				Route        string `json:"http_route"`
				Status       int    `json:"http_status"`
				ResponseCode string `json:"response_code"`
				ErrorCode    string `json:"error_code"`
			}
			if err := json.NewDecoder(&output).Decode(&e); err != nil {
				t.Fatal(err)
			}
			level := "warning"
			if tc.status == 500 {
				level = "error"
			}
			if e.Event != "login_failed" || e.Level != level || e.RequestID == "" || e.RequestID != res.Header().Get("X-Request-Id") ||
				e.Route != "/api/auth/login" || e.Status != tc.status || e.ResponseCode != tc.responseCode || e.ErrorCode != tc.errorCode {
				t.Errorf("unexpected log event: %+v", e)
			}
		})
	}
}

type diagnosticUsers struct {
	store.UserStore
	err error
}

func (s diagnosticUsers) ValidateCredentials(context.Context, string, string) (*domain.UserInfo, error) {
	return nil, s.err
}

func TestDiagnosticsHTTPFailureAndPanic(t *testing.T) {
	for _, panics := range []bool{false, true} {
		var output bytes.Buffer
		logger := slog.New(errlog.NewHandler(&output, "test", nil))
		router := NewRouter(RouterConfig{TokenPath: "/connect/{resource}"}, RouterOptions{Logger: logger}, Handlers{
			Token: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if panics {
					w.Header().Set("Content-Type", "application/json")
					panic("private-panic-value")
				}
				w.WriteHeader(http.StatusInternalServerError)
			}),
		})
		res := httptest.NewRecorder()
		router.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/connect/private-path?token=private-query", nil))
		log := output.String()
		if res.Code != 500 || !strings.Contains(log, `"http_route":"/connect/{resource}"`) ||
			!strings.Contains(log, `"http_status":500`) || strings.Contains(log, "private-") {
			t.Fatalf("status %d, log %s", res.Code, log)
		}
		if panics && (!strings.Contains(log, `"event":"http_panic"`) || !strings.Contains(log, `"stack":`)) {
			t.Errorf("missing safe panic trace: %s", log)
		}
		if !panics && !strings.Contains(log, `"event":"http_error"`) {
			t.Errorf("missing HTTP failure event: %s", log)
		}
	}
}
