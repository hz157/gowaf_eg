package gowaf

import (
	"encoding/json"
	"log"
)

var (
	supportField = []string{
		"Host",
		"Referer",
		"Url",
		"User-Agent",
		"Content-Type",
	}
)

var (
	SuccessResp = &WafProxyResp{
		RetCode: WAF_PASS,
	}
)

var (
	GroupRule = NewRuleList()

	CheckList = []RuleCheckHandler{
		GroupRule,
	}
)

type JsonGroupRule struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Empty bool   `json:"empty"`
	Val   string `json:"val"`
}

type JSONRule struct {
	Type     string          `json:"type"`
	Status   string          `json:"status"`
	RuleName string          `json:"rule_name"`
	Desc     string          `json:"desc"`
	Rule     []JsonGroupRule `json:"reg"`
}

type RuleCheckHandler interface {
	CheckRequest(req *WafHttpRequest) *WafProxyResp
	CleanRules()
	HandleRule(j *JSONRule)
}

func handleJson(str string) error {
	log.Println("handle rule file :", str)
	// 转为字节
	bs := []byte(str)
	var r JSONRule
	// 转为json
	if err := json.Unmarshal(bs, &r); err != nil {
		InsertEgLog("ERROR", "Server-HandleRuleJson", err.Error())
		return err
	}
	GroupRule.HandleRule(&r)
	return nil
}

// 初始化规则
func InitRule() error {
	log.Println("InitRule")
	rules, err := GetWafRule()
	if err != nil {
		return err
	}
	for _, rule := range rules {
		handleJson(rule)
	}
	return nil
}
