package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"server_torii/internal/iptrie"
	"server_torii/internal/rules"
	"server_torii/internal/urllist"
	"strings"
)

// LoadRules Load all rules from the specified path
func LoadRules(rulePath string) (*RuleSet, error) {
	rs := NewRuleSet()

	// Load IP Allow List
	ipAllowFile := filepath.Join(rulePath, "IP_AllowList.conf")
	if err := loadIPRules(ipAllowFile, rs.IPAllowRule.Trie); err != nil {
		return nil, err
	}

	// Load IP Block List
	ipBlockFile := filepath.Join(rulePath, "IP_BlockList.conf")
	if err := loadIPRules(ipBlockFile, rs.IPBlockRule.Trie); err != nil {
		return nil, err
	}

	// Load IP CAPTCHA List (optional when disabled).
	ipCaptchaFile := filepath.Join(rulePath, "IP_CAPTCHAList.conf")
	ipCaptchaErr := loadIPRules(ipCaptchaFile, rs.IPCAPTCHARule.Trie)
	if ipCaptchaErr != nil && !os.IsNotExist(ipCaptchaErr) {
		return nil, fmt.Errorf("IPCAPTCHA list: %w", ipCaptchaErr)
	}

	// Load URL Allow List
	urlAllowFile := filepath.Join(rulePath, "URL_AllowList.conf")
	if err := loadURLRules(urlAllowFile, rs.URLAllowRule.List); err != nil {
		return nil, err
	}

	// Load URL Block List
	urlBlockFile := filepath.Join(rulePath, "URL_BlockList.conf")
	if err := loadURLRules(urlBlockFile, rs.URLBlockRule.List); err != nil {
		return nil, err
	}

	// Load URL CAPTCHA List (optional when disabled).
	urlCaptchaFile := filepath.Join(rulePath, "URL_CAPTCHAList.conf")
	urlCaptchaErr := loadURLRules(urlCaptchaFile, rs.URLCAPTCHARule.List)
	if urlCaptchaErr != nil && !os.IsNotExist(urlCaptchaErr) {
		return nil, fmt.Errorf("URLCAPTCHA list: %w", urlCaptchaErr)
	}

	YAMLFile := filepath.Join(rulePath, "Server.yml")
	if err := loadServerRules(YAMLFile, rs); err != nil {
		return nil, err
	}
	if ipCaptchaErr != nil && rs.IPCAPTCHARule.Enabled {
		return nil, fmt.Errorf("IPCAPTCHA list: %w", ipCaptchaErr)
	}
	if urlCaptchaErr != nil && rs.URLCAPTCHARule.Enabled {
		return nil, fmt.Errorf("URLCAPTCHA list: %w", urlCaptchaErr)
	}

	return rs, nil
}

// loadServerRules fills rs, which must come from NewRuleSet, from the site's Server.yml.
//
// A section the file leaves out keeps its rule disabled. A section that is present must be
// complete and valid even when it is disabled, because the connector can enable a check per
// request. Nothing is repaired or skipped: any problem rejects the file.
func loadServerRules(YAMLFile string, rs *RuleSet) error {
	yamlData, err := os.ReadFile(YAMLFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rules file %s does not exist: %w", YAMLFile, err)
		} else {
			return fmt.Errorf("failed to read rules file %s: %w", YAMLFile, err)
		}
	}

	var wrapper ruleSetWrapper
	if err := decodeStrict(yamlData, &wrapper); err != nil {
		return fmt.Errorf("failed to parse rules file %s: %w", YAMLFile, err)
	}
	if err := mapServerRules(&wrapper, rs); err != nil {
		return fmt.Errorf("invalid rules file %s:\n%w", YAMLFile, err)
	}
	return nil
}

func mapServerRules(wrapper *ruleSetWrapper, rs *RuleSet) error {
	if wrapper.IPAllowRule != nil {
		rs.IPAllowRule.Enabled = wrapper.IPAllowRule.Enabled
	}
	if wrapper.IPBlockRule != nil {
		rs.IPBlockRule.Enabled = wrapper.IPBlockRule.Enabled
	}
	if wrapper.IPCAPTCHARule != nil {
		rs.IPCAPTCHARule.Enabled = wrapper.IPCAPTCHARule.Enabled
	}
	if wrapper.URLAllowRule != nil {
		rs.URLAllowRule.Enabled = wrapper.URLAllowRule.Enabled
	}
	if wrapper.URLCAPTCHARule != nil {
		rs.URLCAPTCHARule.Enabled = wrapper.URLCAPTCHARule.Enabled
	}
	if wrapper.URLBlockRule != nil {
		rs.URLBlockRule.Enabled = wrapper.URLBlockRule.Enabled
	}
	if wrapper.CAPTCHARule != nil {
		if err := mapCaptchaRule(wrapper.CAPTCHARule, rs.CAPTCHARule); err != nil {
			return err
		}
	}
	if err := validateListCaptchaDependencies(wrapper.CAPTCHARule, rs); err != nil {
		return err
	}
	if wrapper.VerifyBotRule != nil {
		*rs.VerifyBotRule = *wrapper.VerifyBotRule
	}
	if wrapper.ExternalMigrationRule != nil {
		if err := validateStruct(wrapper.ExternalMigrationRule, "ExternalMigration"); err != nil {
			return err
		}
		*rs.ExternalMigrationRule = *wrapper.ExternalMigrationRule
	}
	if wrapper.AdaptiveTrafficAnalyzerRule != nil {
		if err := mapAdaptiveTrafficAnalyzerRule(wrapper.AdaptiveTrafficAnalyzerRule, rs.AdaptiveTrafficAnalyzerRule); err != nil {
			return err
		}
	}
	if wrapper.CountryRule != nil {
		if err := mapCountryRule(wrapper.CountryRule, rs.CountryRule); err != nil {
			return err
		}
	}

	if countryRequiresCaptcha(rs.CountryRule) && wrapper.CAPTCHARule == nil {
		return fmt.Errorf("CountryRule captcha action requires CAPTCHA configuration")
	}

	if wrapper.CustomRules != nil {
		if err := mapCustomRules(wrapper.CustomRules, rs.CustomRules); err != nil {
			return err
		}
		if rs.CustomRules.Uses(rules.ActionCaptcha) && wrapper.CAPTCHARule == nil {
			return fmt.Errorf("CustomRules captcha action requires CAPTCHA configuration")
		}
		if rs.CustomRules.Uses(rules.ActionExternal) && wrapper.ExternalMigrationRule == nil {
			return fmt.Errorf("CustomRules external action requires ExternalMigration configuration")
		}
	}

	if wrapper.HTTPFloodRule != nil {
		if err := mapHTTPFloodRule(wrapper.HTTPFloodRule, rs.HTTPFloodRule); err != nil {
			return err
		}
	}
	return nil
}

// validateListCaptchaDependencies rejects CAPTCHA lists without a CAPTCHA section; a section
// that is present has already been validated.
func validateListCaptchaDependencies(captcha *captchaRuleWrapper, rs *RuleSet) error {
	for _, dependency := range []struct {
		name     string
		required bool
	}{
		{"IPCAPTCHA", rs.IPCAPTCHARule.Enabled || !rs.IPCAPTCHARule.Trie.IsEmpty()},
		{"URLCAPTCHA", rs.URLCAPTCHARule.Enabled || (rs.URLCAPTCHARule.List != nil && rs.URLCAPTCHARule.List.Head != nil)},
	} {
		if !dependency.required {
			continue
		}
		if captcha == nil {
			return fmt.Errorf("%s requires CAPTCHA configuration", dependency.name)
		}
	}
	return nil
}

// isSkippableListLine reports whether a trimmed list-file line carries no rule:
// blank lines and "#" comments. URL patterns cannot legitimately start with "#"
// because fragments are never sent to the server.
func isSkippableListLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

// loadIPRules reads the IP rule file and inserts the rules into the trie. A line that is not
// an address or CIDR is an error: skipping it would leave a block or allow rule out unnoticed.
func loadIPRules(filePath string, trie *iptrie.TrieNode) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() // read-only; a Close error cannot lose data

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if isSkippableListLine(line) {
			continue
		}

		ipNet, ok := parseIPRule(line)
		if !ok {
			return fmt.Errorf("%s:%d: invalid IP or CIDR %q", filePath, lineNo, line)
		}
		trie.Insert(ipNet)
	}

	return scanner.Err()
}

// parseIPRule parses a CIDR or a bare address. A bare address becomes a host
// rule sized to its family: /32 for IPv4 (including IPv4-mapped IPv6, which
// net.ParseIP normalizes) and /128 for native IPv6.
func parseIPRule(line string) (*net.IPNet, bool) {
	if strings.Contains(line, "/") {
		_, ipNet, err := net.ParseCIDR(line)
		return ipNet, err == nil
	}
	ip := net.ParseIP(line)
	if ip == nil {
		return nil, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(8*net.IPv4len, 8*net.IPv4len)}, true
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len)}, true
}

// loadURLRules loads URL rules from the specified file. A regex that does not compile is an error.
func loadURLRules(filePath string, list *urllist.URLRuleList) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() // read-only; a Close error cannot lose data

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if isSkippableListLine(line) {
			continue
		}
		// check if the line is a regex
		isRegex := false
		if strings.HasPrefix(line, "^") || strings.HasSuffix(line, "$") || strings.ContainsAny(line, ".*+?()[]{}|\\") {
			isRegex = true
		}
		var compiled *regexp.Regexp
		if isRegex {
			compiled, err = regexp.Compile(line)
			if err != nil {
				return fmt.Errorf("%s:%d: invalid regex %q: %w", filePath, lineNo, line, err)
			}
		}
		rule := &urllist.URLRule{
			Pattern: line,
			IsRegex: isRegex,
			Regex:   compiled,
		}
		list.Append(rule)
	}

	return scanner.Err()
}

// LoadSiteRules loads the rules of every configured site, keyed by site ID.
func LoadSiteRules(cfg *MainConfig) (map[string]*RuleSet, error) {
	siteRules := make(map[string]*RuleSet)

	// Check if any sites are configured
	if len(cfg.Sites) == 0 {
		return nil, fmt.Errorf("no sites configured in torii.yml")
	}

	// Load rules for each configured site
	for i, site := range cfg.Sites {
		if !ValidSiteID(site.ID) {
			return nil, fmt.Errorf("sites[%d]: invalid id %q: use letters, digits and underscores, at most %d characters", i, site.ID, MaxSiteIDLength)
		}
		if _, exists := siteRules[site.ID]; exists {
			return nil, fmt.Errorf("sites[%d]: duplicate id %q", i, site.ID)
		}
		ruleSet, err := LoadRules(site.RulePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules for site %s: %w", site.ID, err)
		}
		ruleSet.ID = site.ID
		siteRules[site.ID] = ruleSet
	}

	if cfg.DefaultSite != "" {
		if _, exists := siteRules[cfg.DefaultSite]; !exists {
			return nil, fmt.Errorf("default_site %q is not one of the configured sites", cfg.DefaultSite)
		}
	}

	return siteRules, nil
}
