package traefik_protector_mirror

import (
	"fmt"
	"net/http"
	"strings"
)

var (
	defaultDeniedPathPrefixes = []string{
		"/.env",
		"/.git/",
		"/wp-config.php",
		"/phpmyadmin",
		"/vendor/phpunit/",
	}
	defaultDeniedUserAgentSubstrings = []string{
		"sqlmap",
		"nikto",
		"wpscan",
		"acunetix",
		"masscan",
	}
)

// PrefilterRules defines low-latency first-line checks.
type PrefilterRules struct {
	URILengthMax         int      `json:"uriLengthMax"`
	QueryLengthMax       int      `json:"queryLengthMax"`
	QueryParamCountMax   int      `json:"queryParamCountMax"`
	HeaderValueLengthMax int      `json:"headerValueLengthMax"`
	DeniedPathPrefixes   []string `json:"deniedPathPrefixes"`
	DeniedUserAgentSubs  []string `json:"deniedUserAgentSubstrings"`
}

type prefilterDecision struct {
	Matched bool
	Rule    string
	Reason  string
}

func defaultPrefilterRules() PrefilterRules {
	pathPrefixes := make([]string, len(defaultDeniedPathPrefixes))
	copy(pathPrefixes, defaultDeniedPathPrefixes)
	uaSubs := make([]string, len(defaultDeniedUserAgentSubstrings))
	copy(uaSubs, defaultDeniedUserAgentSubstrings)

	return PrefilterRules{
		URILengthMax:         2048,
		QueryLengthMax:       2048,
		QueryParamCountMax:   32,
		HeaderValueLengthMax: 4096,
		DeniedPathPrefixes:   pathPrefixes,
		DeniedUserAgentSubs:  uaSubs,
	}
}

func (c *Config) effectivePrefilterMode() string {
	mode := strings.ToLower(strings.TrimSpace(c.PrefilterMode))
	if mode == "enforce" {
		return "enforce"
	}
	return "detect"
}

func (c *Config) prefilterFailClosed() bool {
	return strings.EqualFold(strings.TrimSpace(c.PrefilterFailMode), "closed")
}

func evaluatePrefilter(cfg *Config, rules PrefilterRules, req *http.Request) (prefilterDecision, error) {
	if cfg == nil || !cfg.PrefilterEnabled {
		return prefilterDecision{}, nil
	}
	if req == nil || req.URL == nil {
		return prefilterDecision{}, fmt.Errorf("missing request URL")
	}

	requestURI := req.URL.RequestURI()
	if rules.URILengthMax > 0 && len(requestURI) > rules.URILengthMax {
		return prefilterDecision{Matched: true, Rule: "uri_length_exceeded", Reason: "request URI length exceeds configured maximum"}, nil
	}

	rawQuery := req.URL.RawQuery
	if rules.QueryLengthMax > 0 && len(rawQuery) > rules.QueryLengthMax {
		return prefilterDecision{Matched: true, Rule: "query_length_exceeded", Reason: "query length exceeds configured maximum"}, nil
	}

	if rules.QueryParamCountMax > 0 {
		count := 0
		if rawQuery != "" {
			count = strings.Count(rawQuery, "&") + 1
		}
		if count > rules.QueryParamCountMax {
			return prefilterDecision{Matched: true, Rule: "query_param_count_exceeded", Reason: "query parameter count exceeds configured maximum"}, nil
		}
	}

	if rules.HeaderValueLengthMax > 0 {
		for key, values := range req.Header {
			for _, value := range values {
				if len(value) > rules.HeaderValueLengthMax {
					return prefilterDecision{Matched: true, Rule: "header_value_length_exceeded", Reason: fmt.Sprintf("header %s exceeds configured maximum", key)}, nil
				}
			}
		}
	}

	pathLower := strings.ToLower(req.URL.Path)
	for _, prefix := range rules.DeniedPathPrefixes {
		normalized := strings.ToLower(strings.TrimSpace(prefix))
		if normalized == "" {
			continue
		}
		if strings.HasPrefix(pathLower, normalized) {
			return prefilterDecision{Matched: true, Rule: "denied_path", Reason: fmt.Sprintf("path matched denied prefix %s", normalized)}, nil
		}
	}

	uaLower := strings.ToLower(req.Header.Get("User-Agent"))
	for _, sub := range rules.DeniedUserAgentSubs {
		normalized := strings.ToLower(strings.TrimSpace(sub))
		if normalized == "" {
			continue
		}
		if strings.Contains(uaLower, normalized) {
			return prefilterDecision{Matched: true, Rule: "denied_user_agent", Reason: fmt.Sprintf("user-agent contains denied token %s", normalized)}, nil
		}
	}

	return prefilterDecision{}, nil
}
