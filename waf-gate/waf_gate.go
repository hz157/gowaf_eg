package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/hz157/gowaf"
	"github.com/natefinch/lumberjack"
)

type StartConfig struct {
	Gate  Gate
	Redis Redis
}

type Gate struct {
	GateId string
}

type Redis struct {
	Host     string
	Port     string
	Password string
}

var (
	confFile = flag.String("c", "./waf_gate.conf", "Config file")
	logPath  = flag.String("l", "./log", " log path")
)

func main() {
	flag.Parse()

	// 读取启动配置
	sc := StartConfig{}
	if _, err := toml.DecodeFile(*confFile, &sc); err != nil {
		// 本地日志记录
		log.Println("ERROR", err)
		return
	}
	// 初始化Redis数据库
	gowaf.RedisInit(sc.Redis.Host+":"+sc.Redis.Port, sc.Redis.Password)

	// 读取失败
	sys, err := gowaf.ReadSysConfig()
	if err != nil {
		log.Println("ERROR", err)
	}

	// 初始化Mysql 数据库
	port, _ := strconv.Atoi(sys.Mysql.Port)
	gowaf.MysqlInit(sys.Mysql.Host, sys.Mysql.Database, sys.Mysql.Username, sys.Mysql.Password, port)

	// 设置日志输出
	log.SetOutput(&lumberjack.Logger{
		Filename:   *logPath + "/waf_gate.log",
		MaxSize:    10,
		MaxBackups: 10,
		MaxAge:     30,
	})

	c, _ := gowaf.ReadGateConfig(sc.Gate.GateId)

	log.Println(c)

	// 启动 pprof 监听
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:60060", nil))
	}()

	// 初始化 WAF 配置
	gowaf.InitConfig(c.WAFRPC)
	gowaf.WaitServerNotify()

	// 添加上游服务器
	for _, it := range c.Gate.UpstreamList {
		gowaf.UpStream.Add(&gowaf.RouterItem{
			Key: it,
		})
	}

	// 等待上游服务器初始化完成
	gowaf.UpStream.WaitNotify()

	// 启动 HTTP 服务器
	server := &http.Server{
		Addr:           c.Gate.GateHttpAddress,
		IdleTimeout:    3 * time.Minute,
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		MaxHeaderBytes: 20 * 1024 * 1024,
		Handler:        gowaf.WafHandler,
	}

	// 启动 HTTP 服务器
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			fmt.Println("Listen and serve error ", err.Error())
		}
	}()

	// 检测引擎心跳定时器：每50毫秒执行一次
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			// 写入Redis
			gowaf.SurvivalHeartbeat("gate", c.Gate.Domain, sc.Gate.GateId)
		}
	}()

	// 如果配置了启用 HTTPS
	if c.Gate.StartHttps {
		cfg := &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(c.Gate.CertFile, c.Gate.KeyFile)
				if err != nil {
					return nil, err
				}
				return &cert, nil
			},
		}

		httpsServer := http.Server{
			Addr:           c.Gate.GateHttpsAddress,
			IdleTimeout:    3 * time.Minute,
			ReadTimeout:    5 * time.Minute,
			WriteTimeout:   5 * time.Minute,
			MaxHeaderBytes: 20 * 1024 * 1024,
			Handler:        gowaf.WafHandler,
			TLSConfig:      cfg,
		}
		fmt.Println("Https start at ", c.Gate.GateHttpsAddress)
		log.Fatal(httpsServer.ListenAndServeTLS("", ""))
	}

	select {}
}
