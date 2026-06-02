package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestWriteJSONError_Shape(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONError(rr, http.StatusBadRequest, ErrInvalidRequest, "missing param")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json;charset=UTF-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rr.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q", got)
	}
	var body errorBody
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != ErrInvalidRequest || body.ErrorDescription != "missing param" {
		t.Errorf("body = %+v", body)
	}
}

func TestWriteInvalidClient_StatusAndWWWAuthenticate(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteInvalidClient(rr, "unknown client")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != `Basic realm="auth-server"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
}

func TestRedirectError_PreservesOtherQueryParams(t *testing.T) {
	got := redirectError("https://app.example/cb?foo=bar", ErrAccessDenied, "no", "xyz")
	if got == "" {
		t.Fatal("redirectError returned empty")
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Scheme != "https" || u.Host != "app.example" || u.Path != "/cb" {
		t.Errorf("base url = %s", got)
	}
	q := u.Query()
	if q.Get("foo") != "bar" {
		t.Errorf("foo lost: %s", got)
	}
	if q.Get("error") != ErrAccessDenied {
		t.Errorf("error = %q", q.Get("error"))
	}
	if q.Get("error_description") != "no" {
		t.Errorf("error_description = %q", q.Get("error_description"))
	}
	if q.Get("state") != "xyz" {
		t.Errorf("state = %q", q.Get("state"))
	}
}
