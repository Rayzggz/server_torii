package config

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"regexp"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"
)

type ServerConfig struct {
	Port                           string   `mapstructure:"port"`
	WebPath                        string   `mapstructure:"web_path"`
	RulePath                       string   `mapstructure:"rule_path"`
	ErrorPage                      string   `mapstructure:"error_page"`
	LogPath                        string   `mapstructure:"log_path"`
	NodeName                       string   `mapstructure:"node_name"`
	ConnectingHostHeaders          []string `mapstructure:"connecting_host_headers"`
	ConnectingIPHeaders            []string `mapstructure:"connecting_ip_headers"`
	ConnectingURIHeaders           []string `mapstructure:"connecting_uri_headers"`
	ConnectingCaptchaStatusHeaders []string `mapstructure:"connecting_captcha_status_headers"`
}

type AppConfig struct {
	Server ServerConfig `mapstructure:"server"`
}

var Cfg AppConfig

func InitConfig(defaultConfigContent []byte) {
	// 1. 处理命令行参数
	var configFile string
	pflag.StringVar(&configFile, "config", "", "Path to custom config file")
	pflag.Parse()

	v := viper.New()

	// 2. 加载嵌入的默认配置文件
	if len(defaultConfigContent) > 0 {
		v.SetConfigType("yml")
		if err := v.ReadConfig(bytes.NewBuffer(defaultConfigContent)); err != nil {
			fmt.Printf("加载默认配置失败: %v\n", err)
			os.Exit(1)
		}
	}

	// 3. 加载外部配置文件（如果存在）
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			v.SetConfigFile(configFile)
			if err := v.MergeInConfig(); err != nil {
				fmt.Printf("加载外部配置失败: %v (路径: %s)\n", err, configFile)
				os.Exit(1)
			}
		} else {
			fmt.Printf("警告: 外部配置文件不存在，使用默认配置 (路径: %s)\n", configFile)
		}
	}

	// 4. 映射到结构体
	if err := v.Unmarshal(&Cfg); err != nil {
		fmt.Println("解析配置失败:", err)
		os.Exit(1)
	}
}

// RuleSet stores all rules
type RuleSet struct {
	IPAllowTrie   *dataType.TrieNode
	IPBlockTrie   *dataType.TrieNode
	URLAllowList  *dataType.URLRuleList
	URLBlockList  *dataType.URLRuleList
	CAPTCHARule   *dataType.CaptchaRule
	VerifyBotRule *dataType.VerifyBotRule
	HTTPFloodRule *dataType.HTTPFloodRule
}

// LoadRules Load all rules from the specified path
func LoadRules(rulePath string) (*RuleSet, error) {
	rs := RuleSet{
		IPAllowTrie:   &dataType.TrieNode{},
		IPBlockTrie:   &dataType.TrieNode{},
		URLAllowList:  &dataType.URLRuleList{},
		URLBlockList:  &dataType.URLRuleList{},
		CAPTCHARule:   &dataType.CaptchaRule{},
		VerifyBotRule: &dataType.VerifyBotRule{},
		HTTPFloodRule: &dataType.HTTPFloodRule{},
	}

	// Load IP Allow List
	ipAllowFile := rulePath + "/IP_AllowList.conf"
	if err := loadIPRules(ipAllowFile, rs.IPAllowTrie); err != nil {
		return nil, err
	}

	// Load IP Block List
	ipBlockFile := rulePath + "/IP_BlockList.conf"
	if err := loadIPRules(ipBlockFile, rs.IPBlockTrie); err != nil {
		return nil, err
	}

	// Load URL Allow List
	urlAllowFile := rulePath + "/URL_AllowList.conf"
	if err := loadURLRules(urlAllowFile, rs.URLAllowList); err != nil {
		return nil, err
	}

	// Load URL Block List
	urlBlockFile := rulePath + "/URL_BlockList.conf"
	if err := loadURLRules(urlBlockFile, rs.URLBlockList); err != nil {
		return nil, err
	}

	// Load CAPTCHA Rule
	captchaFile := rulePath + "/CAPTCHA.yml"
	if err := loadCAPTCHARule(captchaFile, rs.CAPTCHARule); err != nil {
		return nil, err
	}

	// Load Verify Bot Rule
	verifyBotFile := rulePath + "/VerifyBot.yml"
	if err := loadVerifyBotRule(verifyBotFile, rs.VerifyBotRule); err != nil {
		return nil, err
	}

	// Load HTTP Flood Rule
	httpFloodFile := rulePath + "/HTTPFlood.yml"
	if err := loadHTTPFloodRule(httpFloodFile, rs.HTTPFloodRule); err != nil {
		return nil, err
	}

	return &rs, nil
}

func loadCAPTCHARule(file string, rule *dataType.CaptchaRule) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, &rule); err != nil {
		return err
	}

	return nil

}

func loadVerifyBotRule(file string, rule *dataType.VerifyBotRule) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return err
	}
	return nil
}

// loadIPRules read the IP rule file and insert the rules into the trie
func loadIPRules(filePath string, trie *dataType.TrieNode) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		var err = file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if !strings.Contains(line, "/") {
			line = line + "/32"
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		trie.Insert(ipNet)
	}

	return scanner.Err()
}

// loadURLRules Load URL rules from the specified file
func loadURLRules(filePath string, list *dataType.URLRuleList) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		var err = file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
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
				// skip invalid regex
				continue
			}
		}
		rule := &dataType.URLRule{
			Pattern: line,
			IsRegex: isRegex,
			Regex:   compiled,
		}
		list.Append(rule)
	}

	return scanner.Err()
}

func loadHTTPFloodRule(file string, rule *dataType.HTTPFloodRule) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	type httpFloodRuleYAML struct {
		HTTPFloodSpeedLimit   []string `yaml:"HTTPFloodSpeedLimit"`
		HTTPFloodSameURILimit []string `yaml:"HTTPFloodSameURILimit"`
	}

	var ymlRule httpFloodRuleYAML
	err = yaml.Unmarshal(data, &ymlRule)
	if err != nil {
		return err
	}

	rule.HTTPFloodSpeedLimit = make(map[int64]int64)
	rule.HTTPFloodSameURILimit = make(map[int64]int64)

	for _, s := range ymlRule.HTTPFloodSpeedLimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		rule.HTTPFloodSpeedLimit[seconds] = limit
	}

	for _, s := range ymlRule.HTTPFloodSameURILimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		rule.HTTPFloodSameURILimit[seconds] = limit
	}

	return nil

}
