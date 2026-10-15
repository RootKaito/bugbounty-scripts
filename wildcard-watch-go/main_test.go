package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(s string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(s)), Header: make(http.Header)}
}
func TestFilters(t *testing.T) {
	v := 70
	low := 69
	nodes := []opportunityNode{{Handle: "yes", OffersBounties: true, StructuredScopeStats: map[string]int{"WILDCARD": 1}, CachedResponseEfficiencyPercentage: &v}, {Handle: "low", OffersBounties: true, StructuredScopeStats: map[string]int{"WILDCARD": 1}, CachedResponseEfficiencyPercentage: &low}, {Handle: "vdp", StructuredScopeStats: map[string]int{"WILDCARD": 1}, CachedResponseEfficiencyPercentage: &v}, {Handle: "no-scope", OffersBounties: true, CachedResponseEfficiencyPercentage: &v}, {Handle: "unknown", OffersBounties: true, StructuredScopeStats: map[string]int{"WILDCARD": 1}}}
	got := filterCandidates(nodes, 70)
	if len(got) != 1 || got[0].Handle != "yes" {
		t.Fatal(got)
	}
}
func TestSeedRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := bootstrapState(p); err != nil {
		t.Fatal(err)
	}
	s, e := loadState(p)
	if e != nil || len(s) == 0 {
		t.Fatal(e)
	}
	t.Logf("seed: %d programs", len(s))
	for k, v := range s {
		if k != v.Handle {
			t.Fatal("key mismatch")
		}
	}
	s["validation"] = Program{Handle: "validation", FirstSeen: "preserved"}
	if e = saveState(p, s); e != nil {
		t.Fatal(e)
	}
	if e = bootstrapState(p); e != nil {
		t.Fatal(e)
	}
	s, e = loadState(p)
	if e != nil || s["validation"].FirstSeen != "preserved" {
		t.Fatal("overwritten")
	}
}
func TestPagination(t *testing.T) {
	calls := 0
	c := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		calls++
		return response(fmt.Sprintf(`{"data":{"opportunities_search":{"total_count":2,"nodes":[{"handle":"p%d"}]}}}`, calls)), nil
	})}
	n, e := fetchAllOpportunities(c, "fake")
	if e != nil || len(n) != 2 || calls != 2 {
		t.Fatal(n, e)
	}
}
func TestTruncatedPageMustFail(t *testing.T) {
	calls := 0
	c := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(`{"data":{"opportunities_search":{"total_count":2,"nodes":[{"handle":"one"}]}}}`), nil
		}
		return response(`{"data":{"opportunities_search":{"total_count":2,"nodes":[]}}}`), nil
	})}
	_, e := fetchAllOpportunities(c, "fake")
	if e == nil {
		t.Fatal("incomplete collection accepted as success")
	}
}
func TestNullDataMustFail(t *testing.T) {
	c := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) { return response(`{"data":null}`), nil })}
	_, e := fetchPage(c, "fake", 0)
	if e == nil {
		t.Fatal("null GraphQL data accepted as success")
	}
}
func TestDeliveryRecovery(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "https://notification.invalid/SECRET")
	t.Setenv("TELEGRAM_BOT_TOKEN", "SECRET")
	t.Setenv("TELEGRAM_CHAT_ID", "123")
	p := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(p, []byte(`{}`), 0600)
	t.Setenv("STATE_PATH", p)
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	discord, telegram := 0, 0
	failing := true
	http.DefaultTransport = transport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "hackerone.com":
			if r.Method == "GET" {
				return response(`<meta name="csrf-token" content="fake"`), nil
			}
			return response(`{"data":{"opportunities_search":{"total_count":1,"nodes":[{"handle":"validation","name":"test","offers_bounties":true,"structured_scope_stats":{"WILDCARD":1},"cached_response_efficiency_percentage":90}]}}}`), nil
		case "notification.invalid":
			discord++
			return response(""), nil
		case "api.telegram.org":
			telegram++
			if failing {
				v := response("SECRET")
				v.StatusCode = 500
				v.Header.Set("Retry-After", "0")
				return v, nil
			}
			return response(`{"ok":true}`), nil
		}
		return nil, fmt.Errorf("unexpected network blocked")
	})
	if err := run(); err == nil {
		t.Fatal("expected pending delivery error")
	}
	s, e := loadState(p)
	if e != nil {
		t.Fatal(e)
	}
	d := s["validation"].Delivery
	if d == nil || !d.Discord || d.Telegram {
		t.Fatal("incorrect channel acknowledgements")
	}
	if discord != 1 || telegram != 3 {
		t.Fatal(discord, telegram)
	}
	failing = false
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if discord != 1 || telegram != 4 {
		t.Fatal("delivered channel repeated", discord, telegram)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if discord != 1 || telegram != 4 {
		t.Fatal("duplicate sends")
	}
}
func TestNotificationErrorsRedacted(t *testing.T) {
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	http.DefaultTransport = transport(func(r *http.Request) (*http.Response, error) {
		v := response("SECRET")
		v.StatusCode = 400
		return v, nil
	})
	err := notifyDiscord("https://example.invalid/SECRET", "test")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}
func TestRetryAfterBudget(t *testing.T) {
	calls := 0
	c := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		calls++
		v := response("")
		v.StatusCode = 429
		v.Header.Set("Retry-After", "3600")
		return v, nil
	})}
	r, _ := http.NewRequest("GET", "https://example.invalid", nil)
	_, e := doRequest(c, r)
	if e == nil || calls != 1 {
		t.Fatal(e, calls)
	}
}
func TestNullState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(p, []byte("null"), 0600)
	if _, e := loadState(p); e == nil {
		t.Fatal("null state accepted")
	}
}
func TestLiveCollection(t *testing.T) {
	if os.Getenv("VALIDATE_LIVE") != "1" {
		t.Skip("opt-in")
	}
	c, e := newHTTPClient()
	if e != nil {
		t.Fatal(e)
	}
	csrf, e := fetchCSRFToken(c)
	if e != nil {
		t.Fatal(e)
	}
	n, e := fetchAllOpportunities(c, csrf)
	if e != nil {
		t.Fatal(e)
	}
	if len(n) == 0 {
		t.Fatal("zero programs")
	}
	seen := map[string]bool{}
	for _, v := range n {
		if v.Handle == "" || seen[v.Handle] {
			t.Fatal("empty or duplicate handle")
		}
		seen[v.Handle] = true
	}
	t.Logf("live: collected=%d candidates=%d", len(n), len(filterCandidates(n, 70)))
}

func TestTelegramOnly(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "fake")
	t.Setenv("TELEGRAM_CHAT_ID", "123")
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATE_PATH", p)
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	sends := 0
	http.DefaultTransport = transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.telegram.org" {
			sends++
			return response(`{"ok":true}`), nil
		}
		if r.URL.Host != "hackerone.com" {
			t.Fatalf("unexpected destination: %s", r.URL.Host)
		}
		if r.Method == "GET" {
			return response(`<meta name="csrf-token" content="fake"`), nil
		}
		return response(`{"data":{"opportunities_search":{"total_count":1,"nodes":[{"handle":"telegram-only","offers_bounties":true,"structured_scope_stats":{"WILDCARD":1},"cached_response_efficiency_percentage":90}]}}}`), nil
	})
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if sends != 1 {
		t.Fatalf("expected one Telegram send; got %d", sends)
	}
	state, err := loadState(p)
	if err != nil || state["telegram-only"].Delivery == nil || !state["telegram-only"].Delivery.Telegram {
		t.Fatal("missing acknowledgement", err)
	}
}
func TestNoChannels(t *testing.T) {
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	if err := run(); err == nil {
		t.Fatal("expected missing-channel error")
	}
}
