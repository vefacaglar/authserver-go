package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRFGuard_IssueVerify(t *testing.T) {
	g := CSRFGuard{CookieName: "_csrf_profile", Path: "/profile", RequireHTTPS: true}
	rec := httptest.NewRecorder()
	tok, err := g.Issue(rec)
	if err != nil || tok == "" {
		t.Fatalf("Issue() = %q, %v", tok, err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/profile" || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("unexpected cookie attrs: %+v", cookies)
	}

	post := func(field string, withCookie bool) *http.Request {
		form := url.Values{csrfFieldName: {field}}
		r := httptest.NewRequest(http.MethodPost, "/profile", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withCookie {
			r.AddCookie(cookies[0])
		}
		return r
	}
	if !g.Verify(post(tok, true)) {
		t.Error("matching token rejected")
	}
	if g.Verify(post("wrong", true)) {
		t.Error("mismatched token accepted")
	}
	if g.Verify(post(tok, false)) {
		t.Error("missing cookie accepted")
	}
	if g.Verify(post("", true)) {
		t.Error("missing field accepted")
	}
}
