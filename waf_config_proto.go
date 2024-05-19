package gowaf

// 网关结构体
type GateConfig struct {
	GateHttpAddress  string
	StartHttps       bool
	Domain           string
	CertKeyList      [][]string
	CertFile         string
	KeyFile          string
	GateHttpsAddress string
	GateAPIAddress   string
	UpstreamList     []string
}

type WafGateConfig struct {
	Gate   GateConfig
	Redis  Redis
	WAFRPC WAFRPCConfig
}

// 服务端结构体
type WafServerConfig struct {
	WafServerAddress string
	HttpAPIAddress   string
	ServerId         string
}

// 系统配置结构体
type SysConfig struct {
	Mysql       Mysql
	Redis       Redis
	Tps         TPS
	Threshold   Threshold
	BanDuration int
}

type Mysql struct {
	Host     string
	Port     string
	Username string
	Password string
	Database string
}

type Redis struct {
	Host     string
	Port     string
	Password string
}

type TPS struct {
	ThreatbookApiKey string
	AIApiKey         string
	AIType           string
}

type Threshold struct {
	Attack    int
	AI_Attack int
	CC        int
}
