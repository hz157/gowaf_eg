package gowaf

import (
	"errors"
	"time"

	"github.com/kumustone/tcpstream"
)

var routerServer = NewRouter() // 创建一个路由器来管理服务器连接

// 处理服务器通知
func handleServerNotify(n AddrNotify) {
	for _, addr := range n.Address {
		if n.Action == WAF_SERVER_ADD {
			// 添加新的服务器到路由器中
			routerServer.Add(&RouterItem{
				Key:   addr,
				Value: tcpstream.NewSyncClient(addr),
			})
		} else if n.Action == WAF_SERVER_REMOVE {
			// 从路由器中移除服务器
			routerServer.Remove(addr)
		}
	}
}

// 等待服务器通知
func WaitServerNotify() {
	go func() {
		for {
			select {
			case n := <-ServerNotify:
				// 处理收到的服务器通知
				handleServerNotify(n)
			}
		}
	}()
}

// WAF检查函数
func WafCheck(request *WafHttpRequest, timeout time.Duration) (*WafProxyResp, error) {
	// 检查是否需要进行检查
	if !NeedCheck(request.Mark) {
		return nil, errors.New("Need no check")
	}
	// 将请求序列化为JSON格式
	buffer, err := request.MarshalJSON()
	if err != nil {
		return nil, errors.New("request MarshalJSON fail")
	}

	var conn *tcpstream.SyncClient
	// 从路由器中选择一个可用的tcpstream连接
	for i := 0; i < int(routerServer.Size()); i++ {
		if r := routerServer.Select(); r == nil {
			break
		} else {
			if r.Value.(*tcpstream.SyncClient).Stream.State == tcpstream.CONN_STATE_ESTAB {
				conn = r.Value.(*tcpstream.SyncClient)
			}
			r = nil
		}
	}

	// 检查是否成功选择了连接
	if conn == nil {
		return nil, errors.New("No tcpstream available ")
	}

	// 发起调用并等待响应
	respMsg, err := conn.Call(&tcpstream.Message{Body: buffer}, time.Duration(time.Millisecond*200))
	if err != nil {
		return nil, err
	}

	resp := &WafProxyResp{}
	// 反序列化响应
	if err := resp.UnmarshalJSON(respMsg.Body); err != nil {
		return nil, err
	}
	return resp, nil
}
