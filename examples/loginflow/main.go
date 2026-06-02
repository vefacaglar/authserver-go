// Command loginflow is a tiny browser demo client for go-authserver.
//
// It is NOT part of the auth server — it stands in for "the application"
// that would normally consume the OIDC flow. Run the auth server, run
// this, then open http://localhost:8080 and click "Log in". You'll be
// bounced to the auth server's /login, sign in as demo/demo, and land
// back here with your tokens decoded on screen.
//
// Public client + PKCE (S256), stdlib only. Dev/demo use only.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	clientID = "demo-public"
	scope    = "openid profile email offline_access"
)

// addr / redirectURI are overridable so the demo can dodge a busy port.
// They must stay consistent with the demo-public client's registered
// redirect URI in the auth server seed.
var (
	addr        = env("DEMO_ADDR", ":8090")
	redirectURI = env("DEMO_REDIRECT_URI", "http://localhost:8090/callback")
)

// issuer is where the auth server lives. Override with AUTH_ISSUER.
var issuer = env("AUTH_ISSUER", "http://localhost:5175")

// pending maps an in-flight state -> its PKCE verifier. A real client
// would tie this to a session; a map is fine for a single-user demo.
var (
	mu      sync.Mutex
	pending = map[string]string{}
)

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/login", login)
	http.HandleFunc("/callback", callback)
	http.HandleFunc("/logout", logout)
	log.Printf("demo client on http://localhost%s  (issuer=%s)", addr, issuer)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	render(w, `<h1>go-authserver demo client</h1>
		<p>This page is the "application". Click below to start the
		OpenID Connect Authorization Code + PKCE flow.</p>
		<p><a class="btn" href="/login">Log in with go-authserver</a></p>
		<p class="muted">You'll sign in as <code>demo</code> / <code>demo</code>.</p>`)
}

// login generates a PKCE pair + state and redirects the browser to the
// auth server's authorization endpoint.
func login(w http.ResponseWriter, r *http.Request) {
	verifier := randB64(32)
	state := randB64(16)
	mu.Lock()
	pending[state] = verifier
	mu.Unlock()

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	http.Redirect(w, r, issuer+"/connect/authorize?"+q.Encode(), http.StatusFound)
}

// logout redirects the browser to the auth server's end session endpoint.
func logout(w http.ResponseWriter, r *http.Request) {
	hint := r.URL.Query().Get("id_token_hint")
	q := url.Values{}
	q.Set("client_id", clientID)
	// The seed sets http://localhost:8090/ for the demo-public client
	q.Set("post_logout_redirect_uri", "http://localhost:8090/")
	if hint != "" {
		q.Set("id_token_hint", hint)
	}
	http.Redirect(w, r, issuer+"/connect/logout?"+q.Encode(), http.StatusFound)
}

// callback receives ?code&state, exchanges the code for tokens, calls
// userinfo, and renders everything decoded.
func callback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		render(w, fmt.Sprintf(`<h1>Authorization error</h1><pre>%s\n%s</pre>
			<p><a href="/">start over</a></p>`,
			html(e), html(r.URL.Query().Get("error_description"))))
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	mu.Lock()
	verifier, ok := pending[state]
	delete(pending, state)
	mu.Unlock()
	if !ok {
		render(w, `<h1>Bad state</h1><p>Unknown or replayed state.
			<a href="/">start over</a></p>`)
		return
	}

	// --- token exchange ---
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	resp, err := http.PostForm(issuer+"/connect/token", form)
	if err != nil {
		render(w, "<h1>token request failed</h1><pre>"+html(err.Error())+"</pre>")
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		render(w, fmt.Sprintf(`<h1>token endpoint %d</h1><pre>%s</pre>
			<p><a href="/">start over</a></p>`, resp.StatusCode, html(string(body))))
		return
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	_ = json.Unmarshal(body, &tok)

	// --- userinfo with the access token ---
	userinfo := "(no access token)"
	if tok.AccessToken != "" {
		req, _ := http.NewRequest("GET", issuer+"/connect/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		if ur, err := http.DefaultClient.Do(req); err == nil {
			ub, _ := io.ReadAll(ur.Body)
			ur.Body.Close()
			userinfo = pretty(ub)
		}
	}

	render(w, fmt.Sprintf(`<h1>✅ Logged in</h1>
		<p class="muted">token_type=%s · expires_in=%d · scope=%s</p>
		<h2>id_token (decoded)</h2><pre>%s</pre>
		<h2>userinfo</h2><pre>%s</pre>
		<h2>access_token (decoded)</h2><pre>%s</pre>
		<h2>refresh_token (opaque)</h2><pre>%s</pre>
		<p><a class="btn" href="/logout?id_token_hint=%s">Log out</a>
		   <a class="btn" href="/login">Log in again</a>
		   <a href="/">home</a></p>`,
		html(tok.TokenType), tok.ExpiresIn, html(tok.Scope),
		html(decodeJWT(tok.IDToken)),
		html(userinfo),
		html(decodeJWT(tok.AccessToken)),
		html(truncate(tok.RefreshToken, 24)),
		url.QueryEscape(tok.IDToken)))
}

// --- helpers ---

func decodeJWT(t string) string {
	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		return "(not a JWT)"
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	return "header:  " + pretty(h) + "\npayload: " + pretty(p)
}

func pretty(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return string(b)
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "… (" + fmt.Sprint(len(s)) + " chars total)"
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var tmpl = template.Must(template.New("p").Parse(`<!doctype html><html><head>
<meta charset="utf-8"><title>go-authserver demo</title><style>
body{font-family:system-ui,sans-serif;max-width:820px;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
pre{background:#f5f5f7;padding:1rem;border-radius:8px;overflow:auto;font-size:13px}
.btn{display:inline-block;background:#2563eb;color:#fff;padding:.6rem 1rem;border-radius:8px;text-decoration:none;margin-right:.5rem}
.muted{color:#666;font-size:14px}h2{margin-top:1.5rem;font-size:15px;text-transform:uppercase;letter-spacing:.04em;color:#444}
code{background:#eee;padding:.1rem .3rem;border-radius:4px}a{color:#2563eb}
</style></head><body>{{.Body}}<hr><p class="muted">demo client · examples/loginflow · {{.Now}}</p></body></html>`))

func render(w http.ResponseWriter, bodyHTML string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, struct {
		Body template.HTML
		Now  string
	}{template.HTML(bodyHTML), time.Now().Format(time.Kitchen)})
}

func html(s string) string { return template.HTMLEscapeString(s) }
