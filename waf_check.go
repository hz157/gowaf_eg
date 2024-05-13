package gowaf

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"
)

func cloneHeader(ch http.Header) http.Header { // 定义一个函数，用于克隆 HTTP 头部
	h2 := make(http.Header, len(ch)) // 创建一个新的 HTTP 头部，容量与原始 HTTP 头部相同
	for k, vv := range ch {          // 遍历原始 HTTP 头部
		vv2 := make([]string, len(vv)) // 创建一个新的字符串切片，长度与原始字符串切片相同
		copy(vv2, vv)                  // 将原始字符串切片的内容复制到新的字符串切片中
		h2[k] = vv2                    // 将新的字符串切片添加到新的 HTTP 头部中
	}
	return h2 // 返回克隆后的 HTTP 头部
}

const MaxLimitBody int64 = 100 * 1024 // 请求体长度最大值

func GetBody(req *http.Request) []byte {
	if req.ContentLength > MaxLimitBody || req.ContentLength <= 0 { // 检查请求体长度是否超过最大限制或小于等于0
		return []byte("") // 如果超过限制或长度为0，则返回一个空的字节切片
	}
	var originBody []byte                              // 定义一个变量用于存储原始请求体的字节切片
	defer req.Body.Close()                             // 延迟关闭请求体，确保在函数返回前关闭请求体
	if body, err := io.ReadAll(req.Body); err != nil { // 读取请求体
		InsertEgLog("INFO", "Gate-GetBody", "Get body fail: "+err.Error()) // 如果读取失败，则记录错误信息
		return body                                                        // 返回读取的请求体（注意：在错误的情况下这里会返回 nil）
	} else { // 如果读取请求体成功
		originBody = make([]byte, req.ContentLength)   // 创建一个与请求体长度相同的字节切片
		copy(originBody, body)                         // 复制读取的请求体到原始请求体中
		req.Body = io.NopCloser(bytes.NewReader(body)) // 将读取的请求体重新封装成一个新的 ReadCloser，并设置给原始请求的 Body 字段
		return originBody                              // 返回原始请求体
	}
}

func CheckCCAttack(ip string) {
	s, _ := ReadSysConfig()
	// CC阈值检测
	count, _ := ReadReqAddressCount(ip)
	if count >= s.Threshold.CC {
		WriteBlockIP(ip)
	} else {
		WriteReqAddressCount(ip)
	}
	// 攻击阈值检测
	count, _ = ReadAttackCount(ip)
	if count >= s.Threshold.Attack {
		WriteBlockIP(ip)
	}
	// AI攻击阈值检测
	count, _ = ReadAiAttackCount(ip)
	if count >= s.Threshold.AI_Attack {
		WriteBlockIP(ip)
	}
}

func Check(req *http.Request) *WafProxyResp {
	// 创建一个 WafHttpRequest 结构体实例，用于传递给 WafCheck 函数进行检查
	wafReq := &WafHttpRequest{
		Mark:          req.Host,                  // 设置请求标记为请求的主机名
		Method:        req.Method,                // 设置请求方法为原始请求的方法
		Scheme:        req.URL.Scheme,            // 设置请求协议为原始请求 URL 的协议
		Url:           req.RequestURI,            // 设置请求 URL 为原始请求的 RequestURI
		Proto:         req.Proto,                 // 设置请求协议版本为原始请求的协议版本
		Host:          req.Host,                  // 设置请求主机为原始请求的主机名
		RemoteAddr:    req.RemoteAddr,            // 设置请求的远程地址为原始请求的远程地址
		ContentLength: uint64(req.ContentLength), // 设置请求内容长度为原始请求的内容长度
		Header:        cloneHeader(req.Header),   // 克隆原始请求的头部，并设置给 WafHttpRequest 结构体中的 Header 字段
		Body:          GetBody(req),              // 获取原始请求的请求体，并设置给 WafHttpRequest 结构体中的 Body 字段
	}
	// 只保留IP即可，分割远程地址，获取IP部分
	if s := strings.Split(req.RemoteAddr, ":"); len(s) > 0 { // 判断远程地址是否包含端口号
		wafReq.RemoteAddr = s[0] // 如果包含端口号，则将远程地址设置为分割后的第一个部分（即IP部分）
	}
	resp, err := WafCheck(wafReq, time.Duration(20*time.Millisecond))
	if err != nil { // 如果发生错误
		InsertEgLog("ERROR", "Gate-Check", err.Error()) // 记录错误信息（注释掉的日志记录语句）
	}
	return resp
}
