package gowaf

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
)

var apiKey string

func ThreatBookInit(apikey string) {
	apiKey = apikey
}

type Response struct {
	Data         map[string]ThreatDataEntry `json:"data"`
	ResponseCode int                        `json:"response_code"` // 响应正常会返回"0"。
	VerboseMsg   string                     `json:"verbose_msg"`   // 响应正常会返回"Ok"
}

type ThreatDataEntry struct {
	Samples       []string      `json:"samples"`
	TagsClasses   []TagsClass   `json:"tags_classes"`  // 相关攻击团伙或安全事件信息
	Judgments     []string      `json:"judgments"`     // 从威胁情报中分析
	Intelligences Intelligences `json:"intelligences"` // 威胁情报
	Scene         string        `json:"scene"`         // 应用场景。如：企业专线，数据中心等
	Basic         Basic         `json:"basic"`         // 运营商及国家信息
	// Cas           []Cas         `json:"cas"`             // SSL相关证书信息
	UpdateTime string `json:"update_time"` // 情报的最近更新时间
	// RdnsList      []string `json:"rdns_list"`       // Rdns记录
	SumCurDomains string `json:"sum_cur_domains"` // 反查当前域名数量
}

type TagsClass struct {
	Tags     []string `json:"tags"`      // 标签类别，如"industry(行业)"、"gangs（团伙）"、"virus_family（家族）"等
	TagsType string   `json:"tags_type"` // 具体的攻击团伙或安全事件标签，例如：APT、海莲花等
}

type Intelligences struct {
	ThreatbookLab []ThreatSource `json:"threatbook_lab"` // 微步在线情报
	XReward       []ThreatSource `json:"x_reward"`       // X情报社区奖励计划来源情报
	OpenSource    []ThreatSource `json:"open_source"`    // 开源情报
}

type ThreatSource struct {
	Source     string      `json:"source"`      // 情报来源
	Confidence int         `json:"confidence"`  // 可信度评分
	Expired    bool        `json:"expired"`     // 布尔类型，false代表情报仍在有效期，true表示情报已过期。
	IntelTags  []TagsClass `json:"intel_tags"`  // 该条情报的标签信息，包含相关攻击团伙或安全事件等。JSON数组，每个item的字段定义同"tag_classes"。
	FindTime   string      `json:"find_time"`   // 发现时间
	IntelTypes []string    `json:"intel_types"` // 威胁类型
	UpdateTime string      `json:"update_time"` // 更新时间
}

type Basic struct {
	Carrier  string   `json:"carrier"`  // 运营商/服务商
	Location Location `json:"location"` // ip对应的位置信息
}

type Location struct {
	Country     string `json:"country"`      // 国家
	Province    string `json:"province"`     // 省
	City        string `json:"city"`         // s城市
	Lng         string `json:"lng"`          // 经度
	Lat         string `json:"lat"`          // 纬度
	CountryCode string `json:"country_code"` // 国家代码
}

func FilterIntelType(threatSource ThreatSource) bool {
	if threatSource.Expired || threatSource.Confidence <= 50 { // expired == true情报已过期或是可信度少于50放弃情报
		return false
	}

	for _, intelType := range threatSource.IntelTypes {
		switch intelType {
		case "Zombie", "傀儡机", "Spam", "垃圾邮件", "Scanner", "扫描", "Suspicious", "可疑", "C2", "远控", "Botnet", "僵尸网络", "Hijacked", "劫持", "Phishing", "钓鱼", "Malware", "恶意软件", "Exploit", "漏洞利用", "Compromised", "失陷主机", "Suspicious-矿池相关", "MiningPool", "公共矿池", "CoinMiner", "私有矿池", "Suspicious Application", "潜在有害应用程序", "Suspicious Website", "潜在有害站点", "SSH Brute Force", "SSH暴力破解", "FTP Brute Force", "FTP暴力破解", "SMTP Brute Force", "SMTP暴力破解", "Http Brute Force", "HTTP AUTH暴力破解", "Web Login Brute Force", "撞库":
			return true
		case "Whitelist", "白名单", "Reverse Proxy", "反向代理", "Fake Website", "仿冒网站", "Sinkhole C2", "安全机构接管 C2", "HTTP Proxy", "HTTP代理", "HTTP Proxy In", "HTTP代理入口", "HTTP Proxy Out", "HTTP代理出口", "Socks Proxy", "Socks代理", "Socks Proxy In", "Socks代理入口", "Socks Proxy Out", "Socks代理出口", "VPN", "VPN代理", "VPN In", "VPN入口", "VPN Out", "VPN出口", "Tor", "Tor代理", "Tor Proxy In", "Tor入口", "Tor Proxy Out", "Tor出口", "Bogon", "保留地址", "FullBogon", "未启用IP", "Gateway", "网关", "IDC", "IDC服务器", "Dynamic IP", "动态IP", "Edu", "教育", "DDNS", "动态域名", "Mobile", "移动基站", "Search Engine Crawler", "搜索引擎爬虫", "CDN", "CDN服务器", "Advertisement", "广告", "DNS", "DNS服务器", "BTtracker", "BT服务器", "Backbone", "骨干网", "ICP", "ICP备案", "IoT Device", "物联网设备", "Game Server", "游戏服务器", "CloudWAF", "云WAF":
			return false
		default:
			return false
		}
	}

	return false
}

func GetThreatSource(threatData ThreatDataEntry) []ThreatSource {
	var result []ThreatSource
	for _, threatSource := range threatData.Intelligences.ThreatbookLab {
		// 执行匹配
		if FilterIntelType(threatSource) {
			// 威胁类型匹配成功，采取相应的操作
			fmt.Println("Threat matched - ThreatbookLab:", threatSource)
			result = append(result, threatSource)
		}
	}

	for _, threatSource := range threatData.Intelligences.XReward {
		// 执行匹配
		if FilterIntelType(threatSource) {
			// 威胁类型匹配成功，采取相应的操作
			result = append(result, threatSource)
		}
	}

	for _, threatSource := range threatData.Intelligences.OpenSource {
		// 执行匹配
		if FilterIntelType(threatSource) {
			// 威胁类型匹配成功，采取相应的操作
			result = append(result, threatSource)
		}
	}
	return result
}

func GetThreat(ip, lang string) (*ThreatDataEntry, error) {
	if isPrivateIP(ip) {
		return nil, nil
	}
	fmt.Println("请求微步接口")
	if lang == "" {
		lang = "en"
	}
	url := fmt.Sprintf("https://api.threatbook.cn/v3/ip/query?apikey=%s&resource=%s&lang=%s", apiKey, ip, lang)
	response, err := http.Get(url)
	if err != nil {
		InsertEgLog("ERROR", "Gate-ThreatBook", fmt.Sprintf("Error sending request: {%v}", err.Error()))
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		InsertEgLog("ERROR", "Gate-ThreatBook", fmt.Sprintf("Error reading response body: %v", err.Error()))
		return nil, err
	}

	var responseData Response
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		InsertEgLog("ERROR", "Gate-ThreatBook", fmt.Sprintf("Error unmarshalling JSON: %v", err.Error()))
		return nil, err
	}

	dataEntry, exists := responseData.Data[ip]
	if !exists {
		return nil, fmt.Errorf("no data found for IP: %s", ip)
	}

	return &dataEntry, nil
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, private24, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16, _ := net.ParseCIDR("192.168.0.0/16")
	_, private127, _ := net.ParseCIDR("127.0.0.1/32")
	return private24.Contains(ip) || private20.Contains(ip) || private16.Contains(ip) || private127.Contains(ip)
}
