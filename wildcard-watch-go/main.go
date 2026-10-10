// Varre hackerone.com/opportunities/all via GraphQL direto (sem browser) por
// programas Bounty + escopo Wildcard + boa response efficiency, e notifica
// Discord + Telegram só o que for genuinamente novo desde a última execução.
//
// Reescrito em Go a partir da versão Playwright/Python: a página é uma SPA
// React, mas a query que ela usa pra popular os cards (operationName
// DiscoveryQuery) é pública e aceita paginação via from/size — dá pra chamar
// direto, sem Chromium. Isso elimina o crash de memória que a versão com
// browser sofria em containers com pouca RAM (ver histórico do projeto).
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	baseURL    = "https://hackerone.com"
	pageURL    = baseURL + "/opportunities/all"
	graphqlURL = baseURL + "/graphql"
	pageSize   = 100
	userAgent  = "Mozilla/5.0 (compatible; WildcardWatch/2.0; +https://github.com/RootKaito/bugbounty-scripts)"
)

var csrfRegex = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)"`)

// seedState é um snapshot do state conhecido no momento da migração da
// versão Python/Playwright pra Go, embutido no binário. bootstrapState usa
// isso só na primeira execução contra um volume vazio, pra não re-notificar
// como "novo" tudo que já tinha sido visto antes da troca.
//go:embed seed_state.json
var seedState []byte

// Query e fragments capturados ao vivo da página (DevTools), verbatim —
// a API não documenta isso publicamente, então qualquer alteração de schema
// do lado do HackerOne pode quebrar isso e exige recapturar.
const discoveryQuery = `query DiscoveryQuery($query: OpportunitiesQuery!, $filter: QueryInput!, $from: Int, $size: Int, $sort: [SortInput!], $post_filters: OpportunitiesFilterInput) {
  me {
    id
    ...OpportunityListMeElastic
    __typename
  }
  opportunities_search(
    query: $query
    filter: $filter
    from: $from
    size: $size
    sort: $sort
    post_filters: $post_filters
  ) {
    nodes {
      ... on OpportunityDocument {
        id
        handle
        state
        __typename
      }
      ...OpportunityList
      __typename
    }
    total_count
    __typename
  }
}

fragment OpportunityListMeElastic on User {
  id
  ...OpportunityCardMeElastic
  __typename
}

fragment OpportunityCardMeElastic on User {
  id
  ...BookmarkMe
  ...PrivateOpportunitiesMe
  __typename
}

fragment BookmarkMe on User {
  id
  __typename
}

fragment PrivateOpportunitiesMe on User {
  id
  whitelisted_teams {
    edges {
      node {
        id
        _id
        __typename
      }
      __typename
    }
    __typename
  }
  __typename
}

fragment OpportunityList on OpportunityDocument {
  id
  ...OpportunityCard
  __typename
}

fragment OpportunityCard on OpportunityDocument {
  id
  team_id
  name
  handle
  profile_picture
  triage_active
  publicly_visible_retesting
  allows_private_disclosure
  allows_bounty_splitting
  launched_at
  state
  offers_bounties
  last_updated_at
  currency
  team_type
  minimum_bounty_table_value
  maximum_bounty_table_value
  cached_response_efficiency_percentage
  first_response_time
  structured_scope_stats
  show_response_efficiency_indicator
  submission_state
  resolved_report_count
  campaign {
    id
    campaign_type
    start_date
    end_date
    critical
    target_audience
    __typename
  }
  gold_standard
  awarded_report_count
  awarded_reporter_count
  h1_clear
  idv
  list_opportunity
  __typename
}`

// ---------- tipos da resposta GraphQL ----------

type opportunityNode struct {
	Handle                             string         `json:"handle"`
	Name                               string         `json:"name"`
	OffersBounties                     bool           `json:"offers_bounties"`
	TeamType                           string         `json:"team_type"`
	MinimumBountyTableValue            *int           `json:"minimum_bounty_table_value"`
	MaximumBountyTableValue            *int           `json:"maximum_bounty_table_value"`
	CachedResponseEfficiencyPercentage *int           `json:"cached_response_efficiency_percentage"`
	StructuredScopeStats               map[string]int `json:"structured_scope_stats"`
}

type discoveryResponse struct {
	Data struct {
		OpportunitiesSearch struct {
			Nodes      []opportunityNode `json:"nodes"`
			TotalCount int               `json:"total_count"`
		} `json:"opportunities_search"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// ---------- programa (formato compatível com o state antigo em Python) ----------

type Program struct {
	Handle             string `json:"handle"`
	Name               string `json:"name"`
	URL                string `json:"url"`
	ProgramType        string `json:"program_type"`
	WildcardCount      int    `json:"wildcard_count"`
	BountyMin          *int   `json:"bounty_min"`
	BountyMax          *int   `json:"bounty_max"`
	ResponseEfficiency *int   `json:"response_efficiency"`
	FirstSeen          string `json:"first_seen"`
}

func toProgram(n opportunityNode, firstSeen string) Program {
	programType := "VDP"
	if n.OffersBounties {
		programType = "Bounty"
	}
	return Program{
		Handle:             n.Handle,
		Name:               n.Name,
		URL:                baseURL + "/" + n.Handle,
		ProgramType:        programType,
		WildcardCount:      n.StructuredScopeStats["WILDCARD"],
		BountyMin:          n.MinimumBountyTableValue,
		BountyMax:          n.MaximumBountyTableValue,
		ResponseEfficiency: n.CachedResponseEfficiencyPercentage,
		FirstSeen:          firstSeen,
	}
}

// ---------- coleta via GraphQL ----------

func newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{Jar: jar, Timeout: 30 * time.Second}, nil
}

func fetchCSRFToken(client *http.Client) (string, error) {
	req, err := http.NewRequest(http.MethodGet, pageURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", pageURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s retornou %d", pageURL, resp.StatusCode)
	}

	m := csrfRegex.FindSubmatch(body)
	if m == nil {
		return "", errors.New("csrf-token não encontrado no HTML")
	}
	return string(m[1]), nil
}

func fetchPage(client *http.Client, csrfToken string, from int) (discoveryResponse, error) {
	variables := map[string]interface{}{
		"size": pageSize,
		"from": from,
		"query": map[string]interface{}{},
		"filter": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []interface{}{
					map[string]interface{}{
						"bool": map[string]interface{}{
							"must_not": map[string]interface{}{
								"term": map[string]interface{}{"team_type": "Engagements::Assessment"},
							},
							"should": []interface{}{
								map[string]interface{}{
									"term": map[string]interface{}{"offers_bounties": true},
								},
							},
						},
					},
					nil,
				},
			},
		},
		"sort": []interface{}{
			map[string]interface{}{"field": "launched_at", "direction": "ASC"},
		},
		"post_filters": map[string]interface{}{
			"my_programs":    false,
			"bookmarked":     false,
			"campaign_teams": false,
		},
		"product_area":    "opportunity_discovery",
		"product_feature": "search",
	}

	payload := map[string]interface{}{
		"operationName": "DiscoveryQuery",
		"variables":     variables,
		"query":         discoveryQuery,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return discoveryResponse{}, err
	}

	req, err := http.NewRequest(http.MethodPost, graphqlURL, bytes.NewReader(body))
	if err != nil {
		return discoveryResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.Header.Set("X-Product-Area", "opportunity_discovery")
	req.Header.Set("X-Product-Feature", "search")
	req.Header.Set("Referer", pageURL)

	resp, err := client.Do(req)
	if err != nil {
		return discoveryResponse{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return discoveryResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return discoveryResponse{}, fmt.Errorf("POST /graphql retornou %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}

	var parsed discoveryResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return discoveryResponse{}, fmt.Errorf("decodificando resposta: %w", err)
	}
	if len(parsed.Errors) > 0 {
		return discoveryResponse{}, fmt.Errorf("graphql retornou erro: %s", parsed.Errors[0].Message)
	}
	return parsed, nil
}

func fetchAllOpportunities(client *http.Client, csrfToken string) ([]opportunityNode, error) {
	var all []opportunityNode
	from := 0
	total := -1

	for total == -1 || from < total {
		page, err := fetchPage(client, csrfToken, from)
		if err != nil {
			return nil, fmt.Errorf("página from=%d: %w", from, err)
		}
		if total == -1 {
			total = page.Data.OpportunitiesSearch.TotalCount
			logf("alvo: %d programas", total)
		}
		nodes := page.Data.OpportunitiesSearch.Nodes
		if len(nodes) == 0 {
			break
		}
		all = append(all, nodes...)
		from += len(nodes)
	}

	return all, nil
}

// ---------- filtro ----------

func filterCandidates(nodes []opportunityNode, minResponseEfficiency int) []opportunityNode {
	var out []opportunityNode
	for _, n := range nodes {
		if !n.OffersBounties {
			continue
		}
		if n.StructuredScopeStats["WILDCARD"] <= 0 {
			continue
		}
		eff := 0
		if n.CachedResponseEfficiencyPercentage != nil {
			eff = *n.CachedResponseEfficiencyPercentage
		}
		if eff < minResponseEfficiency {
			continue
		}
		out = append(out, n)
	}
	return out
}

// ---------- state ----------

// bootstrapState grava o seed embutido em path, mas só se path ainda não
// existir — nunca sobrescreve um state real já presente no volume.
func bootstrapState(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // já existe state real, não mexe
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	var probe map[string]Program
	if err := json.Unmarshal(seedState, &probe); err != nil {
		return fmt.Errorf("seed_state.json embutido é inválido: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, seedState, 0o644); err != nil {
		return err
	}
	logf("state não existia em %s — inicializado com seed embutido (%d programas)", path, len(probe))
	return nil
}

func loadState(path string) (map[string]Program, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Program{}, nil
	}
	if err != nil {
		return nil, err
	}
	state := map[string]Program{}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return state, nil
}

func saveState(path string, state map[string]Program) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------- mensagem ----------

func fmtMoney(n *int) string {
	if n == nil {
		return "?"
	}
	s := strconv.Itoa(*n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var groups []string
	for len(s) > 3 {
		groups = append([]string{s[len(s)-3:]}, groups...)
		s = s[:len(s)-3]
	}
	groups = append([]string{s}, groups...)
	out := "$" + strings.Join(groups, ",")
	if neg {
		out = "-" + out
	}
	return out
}

func buildMessage(p Program) string {
	plural := "s"
	if p.WildcardCount == 1 {
		plural = ""
	}
	return fmt.Sprintf(
		"👁️ Nyarlathotep whispers...\n\n🎯 %s\n🌐 %d wildcard domain%s\n💰 %s – %s\n🔥 Good target\n\n🔗 %s",
		p.Name, p.WildcardCount, plural, fmtMoney(p.BountyMin), fmtMoney(p.BountyMax), p.URL,
	)
}

// ---------- envio ----------

func postJSON(url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s retornou %d: %s", url, resp.StatusCode, truncate(string(b), 300))
	}
	return nil
}

func notifyDiscord(webhookURL, content string) error {
	return postJSON(webhookURL, map[string]string{"content": content})
}

func notifyTelegram(token, chatID, content string) error {
	if token == "" || chatID == "" {
		return nil
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	return postJSON(url, map[string]string{"chat_id": chatID, "text": content})
}

// ---------- utilidades ----------

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", time.Now().UTC().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// ---------- main ----------

func main() {
	statePath := getenv("STATE_PATH", "/data/seen_programs.json")
	discordWebhook := os.Getenv("DISCORD_WEBHOOK_URL")
	if discordWebhook == "" {
		fmt.Fprintln(os.Stderr, "DISCORD_WEBHOOK_URL não configurado")
		os.Exit(1)
	}
	telegramToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	telegramChatID := os.Getenv("TELEGRAM_CHAT_ID")
	minResponseEfficiency := getenvInt("MIN_RESPONSE_EFFICIENCY", 70)

	client, err := newHTTPClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro criando client http: %v\n", err)
		os.Exit(1)
	}

	logf("abrindo %s", pageURL)
	csrfToken, err := fetchCSRFToken(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro obtendo csrf token: %v\n", err)
		os.Exit(1)
	}

	nodes, err := fetchAllOpportunities(client, csrfToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro coletando oportunidades: %v\n", err)
		os.Exit(1)
	}
	logf("%d programas coletados", len(nodes))

	candidates := filterCandidates(nodes, minResponseEfficiency)
	logf("%d passam no filtro (Bounty + Wildcard + resposta >= %d%%)", len(candidates), minResponseEfficiency)

	if err := bootstrapState(statePath); err != nil {
		fmt.Fprintf(os.Stderr, "erro inicializando state: %v\n", err)
		os.Exit(1)
	}

	state, err := loadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro carregando state: %v\n", err)
		os.Exit(1)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	var newPrograms []Program
	for _, n := range candidates {
		p := toProgram(n, now)
		if existing, ok := state[p.Handle]; ok {
			p.FirstSeen = existing.FirstSeen
		} else {
			newPrograms = append(newPrograms, p)
		}
		state[p.Handle] = p
	}
	logf("%d novos desde a última execução", len(newPrograms))

	for _, p := range newPrograms {
		msg := buildMessage(p)
		if err := notifyDiscord(discordWebhook, msg); err != nil {
			logf("  erro notificando discord (%s): %v", p.Handle, err)
		}
		if err := notifyTelegram(telegramToken, telegramChatID, msg); err != nil {
			logf("  erro notificando telegram (%s): %v", p.Handle, err)
		}
		logf("  notificado: %s", p.Name)
		time.Sleep(1200 * time.Millisecond)
	}

	if err := saveState(statePath, state); err != nil {
		fmt.Fprintf(os.Stderr, "erro salvando state: %v\n", err)
		os.Exit(1)
	}
	logf("concluído")
}
