package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/hz157/gowaf"
	"github.com/kumustone/tcpstream"
	"github.com/natefinch/lumberjack"
)

type StartConfig struct {
	Server Server
	Redis  Redis
}

type Server struct {
	WafServerAddress string
	HttpAPIAddress   string
	ServerId         string
}

type Redis struct {
	Host     string
	Port     string
	Password string
}

type Threshold struct {
	CC     int
	Attack int
}

const WafMsgVersion uint8 = 1

var (
	confFile  = flag.String("c", "./waf_server.conf", "Config file")
	logPath   = flag.String("l", "./log", " log path")
	qps_count = 0
)

func main() {
	flag.Parse()

	// 读取启动配置
	c := StartConfig{}
	if _, err := toml.DecodeFile(*confFile, &c); err != nil {
		// 本地日志记录
		log.Println("ERROR", err)
		return
	}

	// 初始化Redis数据库
	gowaf.RedisInit(c.Redis.Host+":"+c.Redis.Port, c.Redis.Password)

	s, err := gowaf.ReadSysConfig()
	// 读取失败
	if err != nil {
		log.Println("ERROR", err)
	}

	// 初始化Mysql 数据库
	port, _ := strconv.Atoi(s.Mysql.Port)
	gowaf.MysqlInit(s.Mysql.Host, s.Mysql.Database, s.Mysql.Username, s.Mysql.Password, port)

	defer gowaf.PanicRecovery(true)
	// 本地日志模块
	log.SetOutput(&lumberjack.Logger{
		Filename:   *logPath + "/waf_server.log",
		MaxSize:    10,
		MaxBackups: 10,
		MaxAge:     30,
	})

	// 初始化防火墙规则库
	if err := gowaf.InitRule(); err != nil {
		log.Fatal("InitRule", err.Error())
	}

	// 初始化ThreatBook APIKEY
	gowaf.ThreatBookInit(s.Tps.ThreatbookApiKey)
	gowaf.GPTInit(s.Tps.AIApiKey, s.Tps.AIType)

	// 打印监听
	log.Println("waf-server listen at: ", c.Server.WafServerAddress)
	fmt.Println("waf-server listen at: ", c.Server.WafServerAddress)

	if err := tcpstream.NewTCPServer(c.Server.WafServerAddress, &ServerHandler{}).Serve(); err != nil {
		log.Println("server error: ", err.Error())
		fmt.Println("server error: ", err.Error())
	} else {
		log.Println("waf-server start succesfully")
		fmt.Println("waf-server start succesfully")
	}

	// 检测引擎心跳定时器：每50毫秒执行一次
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			// 写入Redis
			gowaf.SurvivalHeartbeat("server", c.Server.WafServerAddress, c.Server.ServerId)
		}
	}()

	// QPS定时器，每10秒执行一次
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// 获取当前计数器的值并写入 Redis
			gowaf.WriteWhileReqCount(qps_count / 10)
			// 重置计数器为零
			qps_count = 0
		}
	}()

	select {}

}

type ServerHandler struct{}

func IPThreat(ip string) *gowaf.WafProxyResp {
	var resp = &gowaf.WafProxyResp{} // Initialize resp to avoid nil dereference

	// Getting IP threat data
	ipThreatData, err := gowaf.ReadIPThreat(ip)
	if err != nil {
		gowaf.InsertEgLog("ERROR", "IPThreat", err.Error())
		log.Printf("Error reading IP threat data: %v", err)
		return nil // Handle error appropriately
	}

	// Check if ipThreatData is nil or if it contains valid data
	if ipThreatData == nil {
		log.Println("No threat data found, fetching new data")
		go func() {
			// Asynchronous fetching and storing of new threat data
			ipThreatData, err := gowaf.GetThreat(ip, "en")
			if err != nil {
				gowaf.InsertEgLog("ERROR", "IPThreat", err.Error())
				log.Printf("Error getting threat: %v", err)
				return
			}
			if err := gowaf.WriteIPThreat(ip, ipThreatData); err != nil {
				gowaf.WriteLocation(ipThreatData)
				gowaf.InsertEgLog("ERROR", "IPThreat", err.Error())
				log.Printf("Error writing threat data: %v", err)
				return
			}
			gowaf.WriteLocation(ipThreatData)
		}()
		return nil // Consider returning a default response or continue execution
	}
	gowaf.WriteLocation(ipThreatData)

	// Processing threat data
	threatData := gowaf.GetThreatSource(*ipThreatData)
	if len(threatData) > 0 {
		resp.RuleName = "IP-Intelligence"
		resp.Desc = strings.Join(threatData[0].IntelTypes, ",")
		resp.RetCode = gowaf.WAF_INTERCEPT
		return resp
	}
	return nil
}

func IPFM(request *gowaf.WafHttpRequest) *gowaf.WafProxyResp {
	var resp = &gowaf.WafProxyResp{} // Initialize resp to avoid nil dereference
	// 常规正则匹配
	for _, c := range gowaf.CheckList {
		resp = c.CheckRequest(request)
		if resp.RuleName != "" {
			return resp
		}
	}
	return nil
}

func IPBlock(ip string) *gowaf.WafProxyResp {
	var resp = &gowaf.WafProxyResp{} // 初始化resp以避免nil引用

	// 获取数据库中的黑名单IP
	blockIPList, err := gowaf.GetBlockIP()
	if err != nil {
		gowaf.InsertEgLog("ERROR", "IPBlock", err.Error())
		log.Println("IPBlock Error: ", err)
		return nil
	}

	// 获取临时黑名单IP
	tempBlockIPList, err := gowaf.ReadBlockIPs()
	if err != nil {
		gowaf.InsertEgLog("ERROR", "IPBlock", err.Error())
		log.Println("IPBlock Error: ", err)
		return nil
	}

	// 合并blockIPList和tempBlockIPList
	allBlockIPs := append(blockIPList, tempBlockIPList...)

	// 遍历所有黑名单IP，查看是否有匹配
	for _, blockedIP := range allBlockIPs {
		if ip == blockedIP {
			resp.RuleName = "Block-IP"
			resp.Desc = "IP 黑名单"
			resp.RetCode = gowaf.WAF_INTERCEPT
			return resp
		}
	}

	return nil
}

func IPWhite(ip string) bool {
	// 获取数据库中的黑名单IP
	allWhiteIPs, err := gowaf.GetWhiteIP()
	if err != nil {
		gowaf.InsertEgLog("ERROR", "IPBlock", err.Error())
		log.Println("IPBlock Error: ", err)
		return false
	}

	// 遍历所有白名单IP，查看是否有匹配
	for _, whiteIP := range allWhiteIPs {
		if ip == whiteIP {
			return true
		}
	}

	return false
}

func (*ServerHandler) OnData(conn *tcpstream.TcpStream, msg *tcpstream.Message) error {
	// 请求计数器加一
	qps_count++
	fmt.Println(qps_count)
	request := &gowaf.WafHttpRequest{}
	if err := request.UnmarshalJSON(msg.Body); err != nil {
		return err
	}

	var resp *gowaf.WafProxyResp
	// 如果IP不存在白名单内
	if !IPWhite(request.RemoteAddr) {
		// CC攻击检测
		gowaf.CheckCCAttack(request.RemoteAddr)
		// 请求计数
		gowaf.WriteTotalReq()
		// 黑名单检测
		blockResp := IPBlock(request.RemoteAddr)
		if blockResp != nil {
			resp = blockResp
		} else {
			// 常规特征检测
			patternResp := IPFM(request)
			fmt.Println("常规特征检测结果")
			fmt.Println(patternResp)
			if patternResp != nil {
				resp = patternResp
			} else {
				// 微步IP情报处理
				threatResp := IPThreat(request.RemoteAddr)
				fmt.Println("微步IP情报结果")
				fmt.Println(threatResp)
				if threatResp != nil {
					gowaf.AICheck(request)
					// resp = threatResp
				}
			}
		}
	}
	// gowaf.AICheck(request)
	// 如果没有有效的响应，则初始化默认响应
	if resp == nil {
		resp = &gowaf.WafProxyResp{Desc: "No actionable response generated"}
	} else {
		// 写入攻击地址
		gowaf.WriteAttackCount(request.RemoteAddr)
	}

	// 序列化响应并发送
	body, _ := resp.MarshalJSON()
	respMsg := tcpstream.Message{
		Header: tcpstream.ProtoHeader{
			Seq: msg.Header.Seq,
		},
		Body: body,
	}

	return conn.Write(&respMsg)

}

func (*ServerHandler) OnConn(conn *tcpstream.TcpStream) {

}

func (*ServerHandler) OnDisConn(conn *tcpstream.TcpStream) {

}
