package gowaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/net/proxy"
)

var gptKey string

func GPTInit(apikey string) {
	gptKey = apikey
}

// ChatGPTRequest 表示发送到 ChatGPT API 的数据。
type ChatGPTRequest struct {
	Model       string    `json:"model"`
	Message     []Message `json:"messages"`
	Temperature float32   `json:"temperature"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatGPTResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int    `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int         `json:"index"`
		Message      Message     `json:"message"`
		Logprobs     interface{} `json:"logprobs"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	SystemFingerprint string `json:"system_fingerprint"`
}

func ConstructionReq(request *WafHttpRequest) string {
	// 构造请求的起始行
	startLine := fmt.Sprintf("%s http://%s%s %s", request.Method, request.Host, request.Url, request.Proto)

	// 构造请求头部，使用strings.Builder提高效率
	var headersBuilder strings.Builder
	for name, values := range request.Header {
		for _, value := range values {
			headersBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}

	// 构造完整请求
	requestString := fmt.Sprintf("%s\r\n%s\r\n%s", startLine, headersBuilder.String(), request.Body)

	return requestString
}

func AICheck(req *WafHttpRequest) {
	checkString := ConstructionReq(req)
	// 设置正确的 API 端点
	url := "https://api.openai.com/v1/chat/completions"
	// 创建一个新请求
	reqData := ChatGPTRequest{
		Message: []Message{
			{
				Role:    "user",
				Content: checkString,
			},
			{
				Role:    "system",
				Content: "You are an outstanding cybersecurity expert responsible for analyzing and identifying potential threats in data packets. You just need to answer me the attack category and credibility.format {\"attack category\": \"\", \"credibility\": \"low or middle or high\"}, If there is no attack, just reply to null.Only recognize SQL injection, XSS attack, Trojan injection, directory leakage, critical suffix file access, CSRF attack.",
			},
		},
		Model:       "gpt-3.5-turbo",
		Temperature: 0.7,
	}
	reqBody, _ := json.Marshal(reqData)
	gptreq, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	gptreq.Header.Set("Content-Type", "application/json")
	gptreq.Header.Set("Authorization", "Bearer "+gptKey)

	// 创建一个 SOCKS5 代理拨号器
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:7898", nil, proxy.Direct)
	if err != nil {
		log.Println("创建代理拨号器时出错:", err)
		return
	}

	// 使用代理拨号器设置自定义 HTTP 传输
	httpTransport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: httpTransport,
	}

	// 通过代理发送请求
	resp, err := client.Do(gptreq)
	if err != nil {
		log.Println("发送请求到 API 时出错:", err)
		return
	}
	defer resp.Body.Close()

	// 解析响应
	body, _ := ioutil.ReadAll(resp.Body)
	var chatGPTResponse ChatGPTResponse
	_ = json.Unmarshal(body, &chatGPTResponse)

	// 获取 role 为 assistant 的消息
	for _, choice := range chatGPTResponse.Choices {
		if choice.Message.Role == "assistant" {
			// 解析 content 字段为结构体
			var contentData map[string]string
			_ = json.Unmarshal([]byte(choice.Message.Content), &contentData)
			fmt.Println(contentData["attack category"])
			fmt.Println(contentData["credibility"])
			if contentData["attack category"] != "null" || contentData["attack category"] != "" && contentData["credibility"] == "high" || contentData["credibility"] == "middle" {
				WriteAiAttackCount(req.RemoteAddr)
				ret := &WafProxyResp{
					RetCode:  WAF_INTERCEPT,
					RuleName: "AI LLM Check",
					Desc:     contentData["attack category"],
				}
				// 生成UUID
				id := uuid.New().String()
				InsertEgAIAttackRecord(req, id, req.Host, ret.RuleName, ret.Desc)
			}
		}
	}
}
