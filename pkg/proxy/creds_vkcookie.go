package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
)

// ─── Non-anonymous (cookie) cred path ──────────────────────────────────────
//
// When VK disables anonymous call join (the 2026-06-24 outage: okcdn
// vchat.joinConversationByLink rejects every freshly-minted anon token with
// error.webrtc.auth.anonym_token.not_found), the only known working fallback
// is a LOGGED-IN VK web session: the user supplies a burner account's
// `remixsid` cookie, and we mint TURN creds as that authenticated user
// instead of anonymously.
//
// Recipe ported from ildarmaga/pwdtt-client commit 550a6cc:
//
//   remixsid → login.vk.com/?act=web_token            → web access_token
//            → api.vk.com/method/calls.getSettings      → OK.ru public_key
//            → api.vk.com/method/messages.getCallToken  → authed call token + okcdn base
//            → okcdn auth.anonymLogin (session_data carries auth_token) → session_key
//            → okcdn vchat.joinConversationByLink (session_key, NO anonymToken) → turn_server
//
// Default OFF — gated by SetVKCookieAuth(true, "remixsid=…") from the bridge,
// which the iOS app sets only when the user enables cookie auth in Settings
// and a harvested cookie is present. This trades anonymity for connectivity
// (see project_vk_turn_proxy_ios.md / progress_june_24_2026…). NOT for the
// default anonymous flow.

const (
	vkCookieAppID      = "6287487" // VK_WEB app_id (same as the legacy mint apps)
	vkCookieAPIVersion = "5.280"
	vkCookieAppVersion = "1.1"
	okAppKeyDefault    = "CGMMEJLGDIHBABABA"
)

// Package-level cookie-auth state, set from the bridge (mirrors the
// forceLegacyCaptcha pattern). GetVKCreds consults these on fresh fetches.
var (
	cookieAuthEnabled atomic.Bool
	cookieHeaderStore atomic.Value // string — the raw Cookie header, e.g. "remixsid=…"
	cookieAuthFatal   atomic.Value // string — non-empty when the cookie was rejected/expired (re-login required)
	cookieLinksStore  atomic.Value // []string — call-link IDs for the multi-relay cookie pool

	cookieMu    sync.Mutex
	cookieCache = map[string]*cookieCachedCred{} // linkID -> last successful mint (multi-relay)
)

// cookieCachedCred caches one call's minted (multi-relay) cred so both of its
// relays are served from a single mint until the cred nears expiry.
type cookieCachedCred struct {
	creds *TURNCreds
}

// ErrCookieRejected signals that the logged-in cookie is no longer accepted by
// VK (expired, invalidated, or incomplete) — re-login is required. It is
// distinct from a transient network error: GetVKCreds latches it into the
// cookie-auth fatal state (surfaced via Stats.AuthError) so the extension can
// stop the tunnel with a clear message instead of spinning on a dead cookie.
var ErrCookieRejected = errors.New("vk cookie rejected: expired/invalid/incomplete (re-login required)")

// SetVKCookieAuth enables/disables the cookie (logged-in) cred path and sets
// the Cookie header + the call links (one per relay-cluster — see
// cookieCredForSlot). Called from bridge.go (wgSetVKCookieAuth). Clears any
// prior fatal latch + the per-link mint cache — a (re)configure means the app
// supplied a fresh cookie / changed mode / changed the link set.
func SetVKCookieAuth(enabled bool, cookieHeader string, links []string) {
	cookieAuthEnabled.Store(enabled)
	cookieHeaderStore.Store(strings.TrimSpace(cookieHeader))
	cookieAuthFatal.Store("")
	norm := make([]string, 0, len(links))
	for _, l := range links {
		if id := cookieLinkID(l); id != "" {
			norm = append(norm, id)
		}
	}
	cookieLinksStore.Store(norm)
	cookieMu.Lock()
	cookieCache = map[string]*cookieCachedCred{}
	cookieMu.Unlock()
}

func cookieLinks() []string {
	if v, ok := cookieLinksStore.Load().([]string); ok {
		return v
	}
	return nil
}

// cookieLinkID extracts a bare join-link id from a full URL or an id.
func cookieLinkID(s string) string {
	id := strings.TrimSpace(s)
	if i := strings.LastIndex(id, "join/"); i >= 0 {
		id = id[i+len("join/"):]
	}
	id = strings.TrimRight(id, "/")
	if i := strings.IndexAny(id, "?#"); i > 0 {
		id = id[:i]
	}
	return id
}

// cookieCredForSlot returns a SINGLE-relay TURN cred for pool slot `slot`,
// mapping slot -> (call link, relay) deterministically: link = (slot/2) over the
// configured links, relay = slot%2 (2 relays per call, observed). This makes each
// slot stably hold one (okcdn_userid, relay) bucket — each its own ~10-allocation
// quota (2026-06-28 finding) — so the pool spreads conns across relays instead of
// hammering one. Mints lazily per link and caches the multi-relay result (one mint
// serves both relays); re-mints when the cached cred nears expiry. NO captcha.
func cookieCredForSlot(ctx context.Context, slot int) (*TURNCreds, error) {
	ch := vkCookieHeader()
	if ch == "" {
		return nil, fmt.Errorf("no VK cookie stored: %w", ErrCookieRejected)
	}
	links := cookieLinks()
	if len(links) == 0 {
		return nil, fmt.Errorf("cookie auth: no call links configured")
	}
	if slot < 0 {
		slot = 0
	}
	linkIdx := (slot / 2) % len(links)
	relayIdx := slot % 2
	linkID := links[linkIdx]

	cookieMu.Lock()
	defer cookieMu.Unlock()
	cc := cookieCache[linkID]
	if cc == nil || cc.creds == nil || cookieCredStale(cc.creds) {
		creds, err := getVKCredsViaCookies(ctx, linkID, ch)
		if err != nil {
			return nil, err
		}
		cc = &cookieCachedCred{creds: creds}
		cookieCache[linkID] = cc
	}
	addrs := cc.creds.Addresses
	if len(addrs) == 0 {
		return nil, fmt.Errorf("cookie auth: minted cred has no relays")
	}
	addr := addrs[relayIdx%len(addrs)]
	return &TURNCreds{
		Username:  cc.creds.Username,
		Password:  cc.creds.Password,
		Address:   addr,
		Addresses: []string{addr},
	}, nil
}

// cookieCredStale reports whether a cached cookie cred is within the pool's
// expiry buffer of its VK-supplied expiry (encoded in Username) — i.e. it's time
// to re-mint the call. Unparseable expiry → not stale (let the pool drive refresh).
func cookieCredStale(creds *TURNCreds) bool {
	exp, ok := parseCredExpiry(creds.Username)
	if !ok {
		return false
	}
	return time.Until(exp) < credExpiryBuffer
}

func vkCookieHeader() string {
	if v, ok := cookieHeaderStore.Load().(string); ok {
		return v
	}
	return ""
}

// setCookieAuthFatal / clearCookieAuthFatal / CookieAuthFatalError manage the
// "cookie is dead" latch that the iOS app reads via Stats.AuthError.
func setCookieAuthFatal(msg string) { cookieAuthFatal.Store(msg) }

func clearCookieAuthFatal() { cookieAuthFatal.Store("") }

// CookieAuthFatalError returns a non-empty message when cookie auth has hit an
// unrecoverable rejection (the cookie expired/invalid). The extension surfaces
// it via GetStats and stops the tunnel with a user-readable message.
func CookieAuthFatalError() string {
	if v, ok := cookieAuthFatal.Load().(string); ok {
		return v
	}
	return ""
}

// GetVKCredsViaCookies is the exported wrapper used by the standalone
// tools/cookie_test harness (and any caller without its own context).
func GetVKCredsViaCookies(linkID, cookieHeader string) (*TURNCreds, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return getVKCredsViaCookies(ctx, linkID, cookieHeader)
}

func getVKCredsViaCookies(ctx context.Context, linkID, cookieHeader string) (*TURNCreds, error) {
	cookieHeader = strings.TrimSpace(cookieHeader)
	if cookieHeader == "" {
		return nil, fmt.Errorf("empty cookie")
	}
	joinLink := strings.TrimSpace(linkID)
	if joinLink == "" {
		return nil, fmt.Errorf("empty join link")
	}

	client := newFreshSessionClient()
	ua := GetSessionUserAgent()

	// doForm POSTs a form-encoded body to a VK/OK endpoint carrying the
	// logged-in session cookie (and an optional Bearer access token).
	doForm := func(endpoint string, form neturl.Values, bearer string) (map[string]interface{}, error) {
		req, err := fhttp.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.com")
		req.Header.Set("Referer", "https://vk.com/")
		req.Header.Set("Cookie", cookieHeader)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var out map[string]interface{}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("json: %w body=%s", err, truncForLog(string(body), 200))
		}
		if os.Getenv("VK_COOKIE_DEBUG") == "1" {
			log.Printf("vk-cookie: POST %s -> %s", endpoint, truncForLog(string(body), 400))
		}
		return out, nil
	}

	// Step 1: web_token — exchange the session cookie for a web access token.
	log.Printf("vk-cookie: web_token...")
	webResp, err := doForm("https://login.vk.com/?act=web_token",
		neturl.Values{"version": {"1"}, "app_id": {vkCookieAppID}}, "")
	if err != nil {
		return nil, fmt.Errorf("web_token: %w", err)
	}
	vkToken, _ := cookieRespStr(webResp, "data", "access_token")
	if vkToken == "" {
		// Empty token == the cookie is no longer a valid session (or the
		// cookie set is incomplete). Wrap ErrCookieRejected so GetVKCreds
		// latches the fatal "re-login required" state (Stats.AuthError) rather
		// than spinning. Raw response attached for diagnosis.
		return nil, fmt.Errorf("%w: web_token empty access_token; resp=%s", ErrCookieRejected, truncRespMap(webResp))
	}

	// Step 2: calls.getSettings — OK.ru application public_key.
	settingsResp, err := doForm("https://api.vk.com/method/calls.getSettings",
		neturl.Values{"v": {vkCookieAPIVersion}}, vkToken)
	if err != nil {
		return nil, fmt.Errorf("calls.getSettings: %w", err)
	}
	if e := cookieAPIError(settingsResp); e != "" {
		return nil, fmt.Errorf("calls.getSettings: %s", e)
	}
	appKey, _ := cookieRespStr(settingsResp, "response", "settings", "public_key")
	if appKey == "" {
		appKey, _ = cookieRespStr(settingsResp, "response", "public_key")
	}
	if appKey == "" {
		appKey = okAppKeyDefault
	}

	// Step 3: messages.getCallToken — authed call token + okcdn base url.
	callTokResp, err := doForm("https://api.vk.com/method/messages.getCallToken",
		neturl.Values{"v": {vkCookieAPIVersion}, "env": {"production"}}, vkToken)
	if err != nil {
		return nil, fmt.Errorf("messages.getCallToken: %w", err)
	}
	if e := cookieAPIError(callTokResp); e != "" {
		return nil, fmt.Errorf("messages.getCallToken: %s", e)
	}
	authToken, err := cookieRespStr(callTokResp, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("messages.getCallToken: no token (resp=%v)", truncRespMap(callTokResp))
	}
	apiBaseURL, err := cookieRespStr(callTokResp, "response", "api_base_url")
	if err != nil {
		return nil, fmt.Errorf("messages.getCallToken: no api_base_url")
	}
	apiBaseURL = strings.TrimRight(apiBaseURL, "/")
	if !strings.HasSuffix(apiBaseURL, "/fb.do") {
		apiBaseURL += "/fb.do"
	}

	// Step 4: OK.ru anonymLogin — session_data carries the authed call token
	// (this is what distinguishes the logged-in path from the anonymous one).
	deviceID := uuid.New().String()
	sessionData, _ := json.Marshal(map[string]interface{}{
		"version":        3,
		"device_id":      deviceID,
		"client_version": vkCookieAppVersion,
		"client_type":    "SDK_JS",
		"auth_token":     authToken,
	})
	loginResp, err := doForm(apiBaseURL, neturl.Values{
		"method":          {"auth.anonymLogin"},
		"application_key": {appKey},
		"format":          {"JSON"},
		"session_data":    {string(sessionData)},
	}, "")
	if err != nil {
		return nil, fmt.Errorf("auth.anonymLogin: %w", err)
	}
	if e := cookieOKError(loginResp); e != "" {
		return nil, fmt.Errorf("auth.anonymLogin: %s", e)
	}
	sessionKey, err := cookieRespStr(loginResp, "session_key")
	if err != nil {
		return nil, fmt.Errorf("auth.anonymLogin: no session_key (resp=%v)", truncRespMap(loginResp))
	}

	// Step 5: join — TURN creds via session_key (NO anonymToken).
	joinResp, err := doForm(apiBaseURL, neturl.Values{
		"method":          {"vchat.joinConversationByLink"},
		"session_key":     {sessionKey},
		"application_key": {appKey},
		"format":          {"JSON"},
		"joinLink":        {joinLink},
		"isVideo":         {"false"},
		"isAudio":         {"false"},
		"protocolVersion": {"5"},
		"capabilities":    {"2F7F"},
	}, "")
	if err != nil {
		return nil, fmt.Errorf("join: %w", err)
	}
	if e := cookieOKError(joinResp); e != "" {
		return nil, fmt.Errorf("join: %s", e)
	}
	user, err := cookieRespStr(joinResp, "turn_server", "username")
	if err != nil {
		return nil, fmt.Errorf("join: no turn_server.username (resp=%v)", truncRespMap(joinResp))
	}
	pass, err := cookieRespStr(joinResp, "turn_server", "credential")
	if err != nil {
		return nil, fmt.Errorf("join: no turn_server.credential")
	}
	addrs := parseTURNAddrsFromResp(joinResp)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("join: turn_server.urls empty")
	}

	log.Printf("vk-cookie: SUCCESS user=%s addrs=%v", user, addrs)
	return &TURNCreds{Username: user, Password: pass, Address: addrs[0], Addresses: addrs}, nil
}

// ─── small local helpers ───────────────────────────────────────────────────

func cookieRespStr(resp map[string]interface{}, keys ...string) (string, error) {
	var cur interface{} = resp
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("expected map at %q, got %T", k, cur)
		}
		cur = m[k]
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("expected string, got %T", cur)
	}
	return s, nil
}

// cookieAPIError extracts a VK API error ({"error":{"error_code":N,...}}).
func cookieAPIError(resp map[string]interface{}) string {
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		return ""
	}
	code, _ := errObj["error_code"].(float64)
	msg, _ := errObj["error_msg"].(string)
	if code == 0 && msg == "" {
		return ""
	}
	return fmt.Sprintf("error_code=%.0f %s", code, msg)
}

// cookieOKError extracts an OK.ru/okcdn error (top-level {"error_code":N,...}).
func cookieOKError(resp map[string]interface{}) string {
	code, ok := resp["error_code"].(float64)
	if !ok || code == 0 {
		return ""
	}
	msg, _ := resp["error_msg"].(string)
	return fmt.Sprintf("error_code=%.0f %s", code, msg)
}

func parseTURNAddrsFromResp(resp map[string]interface{}) []string {
	ts, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil
	}
	urls, ok := ts["urls"].([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, u := range urls {
		s, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(s, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		out = append(out, addr)
	}
	return out
}

func truncForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func truncRespMap(m map[string]interface{}) string {
	b, _ := json.Marshal(m)
	return truncForLog(string(b), 240)
}
