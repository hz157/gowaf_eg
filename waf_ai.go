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
var aiType string

func GPTInit(apikey string, aitype string) {
	gptKey = apikey
	aiType = aitype
}

// ChatGPTRequest 表示发送到 ChatGPT API 的数据。
type ChatGPTRequest struct {
	Model       string    `json:"model"`
	Message     []Message `json:"messages"`
	Temperature float32   `json:"temperature"`
}

type LlamaRequest struct {
	Message []Message `json:"messages"`
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

	fmt.Println(aiType)
	if aiType == "ChatGPT" {
		handleChatGPTRequest(req, checkString)
	} else {
		handleLlamaRequest(req, checkString)
	}
}

func handleChatGPTRequest(req *WafHttpRequest, checkString string) {
	chatGPTURL := "https://api.openai.com/v1/chat/completions"
	reqData := createChatGPTRequest(checkString)
	respData, err := sendRequest(chatGPTURL, reqData, true)
	if err != nil {
		log.Println("发送请求到 ChatGPT API 时出错:", err)
		return
	}
	processResponse(req, respData)
}

func handleLlamaRequest(req *WafHttpRequest, checkString string) {
	llamaURL := "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/llama_3_70b?access_token=" + gptKey
	reqData := createLlamaRequest(checkString)
	respData, err := sendRequest(llamaURL, reqData, false) // 不需要使用Proxy
	if err != nil {
		log.Println("发送请求到 Llama API 时出错:", err)
		return
	}
	processResponse(req, respData)
}

func createChatGPTRequest(checkString string) []byte {
	reqData := ChatGPTRequest{
		Message: []Message{
			{
				Role:    "user",
				Content: checkString,
			},
			{
				Role:    "system",
				Content: systemPrompt(),
			},
		},
		Model:       "gpt-3.5-turbo",
		Temperature: 0.7,
	}
	reqBody, _ := json.Marshal(reqData)
	return reqBody
}

func createLlamaRequest(checkString string) []byte {
	reqData := LlamaRequest{
		Message: []Message{
			{
				Role:    "user",
				Content: systemPrompt() + "\n" + checkString,
			},
		},
	}
	reqBody, _ := json.Marshal(reqData)
	return reqBody
}

func sendRequest(url string, reqData []byte, useProxy bool) ([]byte, error) {
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqData))
	var client *http.Client
	if useProxy {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+gptKey)
		dialer, err := proxy.SOCKS5("tcp", "192.168.110.15:7898", nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		client = &http.Client{
			Transport: &http.Transport{
				Dial: dialer.Dial,
			},
		}
	} else {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		client = &http.Client{}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func systemPrompt() string {
	return "You are an outstanding cybersecurity expert responsible for analyzing and identifying potential threats in data packets. You just need to answer me the attack category and credibility.format {\"attack category\": \"\", \"credibility\": \"low or middle or high\"}, If there is no attack, just reply to null.Only recognize SQL injection, XSS attack, Trojan injection, directory leakage, critical suffix file access, CSRF attack."
}

func processResponse(req *WafHttpRequest, response []byte) {
	var responseData map[string]interface{}
	err := json.Unmarshal(response, &responseData)
	if err != nil {
		log.Println("Error unmarshalling response:", err)
		return
	}
	fmt.Println("responseData", responseData)

	// 检查是否存在 'result' 字段，如果存在，直接从这个字段获取数据
	if result, exists := responseData["result"].(string); exists {
		var resultData map[string]string
		err = json.Unmarshal([]byte(result), &resultData)
		if err != nil {
			log.Println("Error unmarshalling result content:", err)
			return
		}
		processAttackInfo(req, resultData["attack category"], resultData["credibility"])
	} else {
		choices, ok := responseData["choices"].([]interface{})
		if !ok || len(choices) == 0 {
			log.Println("No choices available or invalid structure")
			return
		}

		firstChoice := choices[0].(map[string]interface{})
		message := firstChoice["message"].(map[string]interface{})
		content := message["content"].(string)

		// 解析 content 字符串到一个新的 map 中
		var contentData map[string]string
		err = json.Unmarshal([]byte(content), &contentData)
		if err != nil {
			log.Println("Error unmarshalling content:", err)
			return
		}
		processAttackInfo(req, contentData["attack category"], contentData["credibility"])
	}
}

// 处理攻击信息和生成响应
func processAttackInfo(req *WafHttpRequest, attackCategory, credibility string) {
	fmt.Println("Attack Category:", attackCategory)
	fmt.Println("Credibility:", credibility)

	if attackCategory != "null" && attackCategory != "" && (credibility == "high" || credibility == "middle") {
		WriteAiAttackCount(req.RemoteAddr)
		ret := &WafProxyResp{
			RetCode:  WAF_INTERCEPT,
			RuleName: "AI LLM Check",
			Desc:     attackCategory,
		}
		// 生成UUID
		id := uuid.New().String()
		InsertEgAIAttackRecord(req, id, req.Host, ret.RuleName, ret.Desc)
	}
}
