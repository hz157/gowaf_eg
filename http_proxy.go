package gowaf

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
)

var UpStream = NewRouter() // UpStream 保存了路由信息

// httpReverse 是一个处理反向代理的对象
var httpReverse = NewMultipleHostReverseProxy()

// NewMultipleHostReverseProxy 创建一个处理多个主机反向代理的对象
func NewMultipleHostReverseProxy() *httputil.ReverseProxy {
	// 调试日志
	debugLog := log.New(os.Stdout, "[Debug]", log.Ldate|log.Ltime|log.Llongfile)

	return &httputil.ReverseProxy{
		ErrorLog: debugLog, // 错误日志

		// 修改请求
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"              // 设置URL协议为http
			req.URL.Host = UpStream.Select().Key // 设置URL主机为选定的上游主机
		},

		// 修改响应
		ModifyResponse: func(resp *http.Response) error {
			return nil
		},

		// 定制Transport
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return http.ProxyFromEnvironment(req)
			},

			// 定制Dial函数
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{
					Timeout:   30 * time.Second, // 超时时间
					KeepAlive: 30 * time.Second, // 连接保持时间
				}).Dial(network, addr)
				if err != nil {
					InsertEgLog("ERROR", "Gate-Proxy", "Error during DIAL:"+err.Error())
				}
				return conn, err
			},

			MaxIdleConnsPerHost: 512,               // 每个主机的最大空闲连接数
			TLSHandshakeTimeout: 300 * time.Second, // TLS握手超时时间
			IdleConnTimeout:     120 * time.Second, // 空闲连接超时时间
		},
	}
}

// HttpHandler 结构体
type HttpHandler struct{}

var (
	WafHandler = &HttpHandler{}
)

// ServeHTTP 方法实现了 http.Handler 接口
func (h *HttpHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	// 打印远程地址
	fmt.Println(req.RemoteAddr)
	// 请求地址与网关启动地址不符返回404
	// if GateConfig.Domain != req.Host {
	// 	resp.WriteHeader(404)
	// }
	ret := Check(req)
	if ret != nil && ret.RetCode == WAF_INTERCEPT { // 如果需要拦截
		// 生成UUID
		id := uuid.New().String()
		InsertEgAttackRecord(req, id, req.Host, ret.RuleName, ret.Desc)
		// 格式化拦截响应界面
		resp.WriteHeader(403)
		fmt.Fprintf(resp, FormatHTML(id))
		return
	}
	// 在这里添加其他逻辑（如检查、处理请求等）

	// 设置包头给后端做业务处理
	req.Header.Set("x-waf-scheme", req.URL.Scheme)        // 设置包头 x-waf-scheme
	req.Header.Set("x-aiwaf-forware-for", req.URL.Scheme) // 设置包头 x-aiwaf-forware-for

	// 反向代理处理请求
	httpReverse.ServeHTTP(resp, req)
}
