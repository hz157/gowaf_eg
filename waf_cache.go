package gowaf

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
)

// Redis DB使用说明
// DB0 WAF系统配置
// DB1 心跳
// DB2 IP请求&QPS记录
// DB3 IP情报
// DB4 IP攻击记录
// DB5 IP黑名单

var redisPool *redis.Pool

// Redis初始化
func RedisInit(redisAddr, redisPwd string) {
	redisPool = &redis.Pool{
		MaxIdle:     10,
		MaxActive:   100,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", redisAddr, redis.DialPassword(redisPwd))
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
}

// 清理Redis数据库-慎用
func ClearRedisDatabases() error {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	for i := 1; i <= 15; i++ {
		// 选择数据库
		if _, err := redisConn.Do("SELECT", i); err != nil {
			return err
		}

		// 清空数据库
		if _, err := redisConn.Do("FLUSHDB"); err != nil {
			return err
		}
	}

	return nil
}

// 更新Redis中地址访问次数 DB2
func WriteReqAddressCount(ip string) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库2（DB2）
	if _, err := redisConn.Do("SELECT", 2); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 使用 INCR 增加 IP 计数器
	if _, err := redisConn.Do("INCR", ip); err != nil {
		log.Println("Failed to increment IP request count in Redis:", err)
		return
	}

	// 检查键的过期时间
	ttl, err := redis.Int(redisConn.Do("TTL", ip))
	if err != nil {
		log.Println("Failed to get TTL for IP:", err)
		return
	}

	// 如果没有设置过期时间（新键），设置过期时间为60秒
	if ttl == -1 {
		if _, err := redisConn.Do("EXPIRE", ip, 60); err != nil {
			log.Println("Failed to set expiration for IP request count in Redis:", err)
		}
	}
}

// 获取Redis数据库中地址访问次数 DB2
func ReadReqAddressCount(ip string) (int, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库2（DB2）
	if _, err := redisConn.Do("SELECT", 2); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 获取 IP 对应的计数器值
	ip_req_count, err := redis.Int(redisConn.Do("GET", ip))
	if err == redis.ErrNil {
		// 如果计数器不存在，则返回 0
		return 0, nil
	}
	if err != nil {
		// 如果发生其他错误，记录日志并返回
		log.Println("Failed to get IP request count from Redis:", err)
		return 0, err
	}
	return ip_req_count, nil
}

// 写入请求次数 DB2
func WriteWhileReqCount(count int) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库2（DB2）
	if _, err := redisConn.Do("SELECT", 2); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 执行 SET 命令，并指定过期时间
	if _, err := redisConn.Do("SET", "qps_count", count); err != nil {
		log.Println("Failed to write QPS to Redis:", err)
	}
}

// 写入请求次数
func WriteTotalReq() {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库2（DB2）
	if _, err := redisConn.Do("SELECT", 2); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 使用 INCR 增加 IP 计数器
	if _, err := redisConn.Do("INCR", "requests_count"); err != nil {
		log.Println("Failed to write QPS to Redis:", err)
		return
	}
}

// WAF引擎存活心跳
func SurvivalHeartbeat(typ string, domain string, random string) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库1（DB1）
	if _, err := redisConn.Do("SELECT", 1); err != nil {
		log.Println("Failed to select Redis database:", err) // 记录错误信息（注释掉的日志记录语句）
	}

	// 获取当前时间
	currentTime := time.Now().Format(time.RFC3339)
	key := ""
	// 网关心跳
	port := strings.Split(domain, ":")[1]
	domain = strings.Split(domain, ":")[0]
	key = typ + "-" + random
	// 使用Hash存储
	if _, err := redisConn.Do("HMSET", key, "domain", domain, "port", port, "time", currentTime); err != nil {
		log.Println("Failed to write heartbeat to Redis:", err) // 记录错误信息（注释掉的日志记录语句）
	}

	// 设置过期时间为1秒
	if _, err := redisConn.Do("EXPIRE", key, 1); err != nil {
		log.Println("Failed to set expiration for heartbeat in Redis:", err) // 记录错误信息（注释掉的日志记录语句）
	}
}

// 读取服务端配置
func ReadServerConfig(serverId string) (*WafServerConfig, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库0（DB0）
	if _, err := redisConn.Do("SELECT", 0); err != nil {
		return nil, err
	}

	// 从Redis中获取配置
	config, err := redis.Values(redisConn.Do("HGETALL", "WafServerConfig-"+serverId))
	if err != nil {
		return nil, err
	}

	// 解析配置并赋值给结构体
	var wafServerConfig WafServerConfig
	for i := 0; i < len(config); i += 2 {
		key := string(config[i].([]byte))
		value := string(config[i+1].([]byte))
		switch key {
		case "ServerId":
			wafServerConfig.ServerId = value
		case "WafServerAddress":
			wafServerConfig.WafServerAddress = value
		case "HttpAPIAddress":
			wafServerConfig.HttpAPIAddress = value
		}
	}

	return &wafServerConfig, nil
}

// 读取系统配置
func ReadSysConfig() (*SysConfig, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库0（DB0）
	if _, err := redisConn.Do("SELECT", 0); err != nil {
		return nil, err
	}

	// 从Redis中获取配置
	config, err := redis.Values(redisConn.Do("HGETALL", "SysConfig"))
	if err != nil {
		return nil, err
	}

	// 解析配置并赋值给结构体
	var sysConfig SysConfig
	for i := 0; i < len(config); i += 2 {
		key := string(config[i].([]byte))
		value := string(config[i+1].([]byte))
		switch key {
		case "Mysql-Host":
			sysConfig.Mysql.Host = value
		case "Mysql-Port":
			sysConfig.Mysql.Port = value
		case "Mysql-Username":
			sysConfig.Mysql.Username = value
		case "Mysql-Password":
			sysConfig.Mysql.Password = value
		case "Mysql-Database":
			sysConfig.Mysql.Database = value
		case "Redis-Host":
			sysConfig.Redis.Host = value
		case "Redis-Port":
			sysConfig.Redis.Port = value
		case "Redis-Password":
			sysConfig.Redis.Password = value
		case "TPS-ThreatbookApiKey":
			sysConfig.Tps.ThreatbookApiKey = value
		case "TPS-AIApiKey":
			sysConfig.Tps.AIApiKey = value
		case "Threshold-Attack":
			threshold, _ := strconv.Atoi(value)
			if err != nil {
				log.Println("Error converting Threshold-Attack:", err)
			}
			sysConfig.Threshold.Attack = threshold
		case "Threshold-AI-Attack":
			threshold, _ := strconv.Atoi(value)
			if err != nil {
				log.Println("Error converting Threshold-Attack:", err)
			}
			sysConfig.Threshold.AI_Attack = threshold
		case "Threshold-CC":
			threshold, _ := strconv.Atoi(value)
			if err != nil {
				log.Println("Error converting Threshold-CC:", err)
			}
			sysConfig.Threshold.CC = threshold
		case "Ban-Duration":
			duration, _ := strconv.Atoi(value)
			if err != nil {
				log.Println("Error converting BanDuration:", err)
			}
			sysConfig.BanDuration = duration
		}
	}

	return &sysConfig, nil
}

// 读取网关配置
func ReadGateConfig(gateId string) (*WafGateConfig, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库0（DB0）
	if _, err := redisConn.Do("SELECT", 0); err != nil {
		return nil, err
	}

	// 从Redis中获取配置
	config, err := redis.Values(redisConn.Do("HGETALL", "WafGateConfig-"+gateId))
	if err != nil {
		return nil, err
	}

	// 解析配置并赋值给结构体
	var wafGateConfig WafGateConfig
	for i := 0; i < len(config); i += 2 {
		key := string(config[i].([]byte))
		value := string(config[i+1].([]byte))
		switch key {
		case "GateHttpAddress":
			wafGateConfig.Gate.GateHttpAddress = value
		case "StartHttps":
			boolValue, err := strconv.ParseBool(value)
			if err != nil {
				// 错误处理: 例如，记录错误、使用默认值等
				log.Printf("Convert StartHttps error: %v\n", err)
			} else {
				wafGateConfig.Gate.StartHttps = boolValue
			}
		case "Domain":
			wafGateConfig.Gate.Domain = value
		case "GateHttpsAddress":
			wafGateConfig.Gate.GateHttpsAddress = value
		case "CertFile":
			wafGateConfig.Gate.CertFile = value
		case "KeyFile":
			wafGateConfig.Gate.KeyFile = value
		case "GateAPIAddress":
			wafGateConfig.Gate.GateAPIAddress = value
		case "CertKeyList":
			wafGateConfig.Gate.CertKeyList = [][]string{}
		case "UpstreamList":
			serverAddrs := strings.Split(value, ",") // Split the string into a slice using comma as the separator
			wafGateConfig.Gate.UpstreamList = serverAddrs
		case "wafrpc_CheckSwitch":
			boolValue, err := strconv.ParseBool(value)
			if err != nil {
				// 错误处理: 例如，记录错误、使用默认值等
				log.Printf("Convert CheckSwitch error: %v\n", err)
			} else {
				wafGateConfig.WAFRPC.CheckSwitch = boolValue
			}
		case "wafrpc_ServerAddr_Address":
			serverAddrs := strings.Split(value, ",") // Split the string into a slice using comma as the separator
			wafGateConfig.WAFRPC.ServerAddr.Address = serverAddrs
		}
	}

	return &wafGateConfig, nil
}

// 写入IP情报
func WriteIPThreat(ip string, dateEntry *ThreatDataEntry) error {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库3（DB3）
	if _, err := redisConn.Do("SELECT", 3); err != nil {
		return err
	}
	serializedData := "PrivateIP"
	if dateEntry != nil {
		// 序列化threatSources
		data, err := json.Marshal(*dateEntry)
		if err != nil {
			log.Println("Serializing threatSources error:", err)
			return err
		}
		serializedData = string(data)
	}
	// 将序列化后的数据存储到Redis
	if _, err := redisConn.Do("SET", ip, serializedData); err != nil {
		log.Println("set redis error:", err)
		return err
	}
	// 设置过期时间为1天（86400秒）
	if _, err := redisConn.Do("EXPIRE", ip, 2592000); err != nil {
		return err
	}

	return nil
}

// 读取IP威胁情报
func ReadIPThreat(ip string) (*ThreatDataEntry, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库3（DB3）
	if _, err := redisConn.Do("SELECT", 3); err != nil {
		log.Printf("select db error: %v", err)
		return nil, err
	}

	// 从Redis中获取序列化的JSON字符串或纯文本
	serializedData, err := redis.Bytes(redisConn.Do("GET", ip))
	if err != nil {
		if err == redis.ErrNil {
			// 键不存在
			return nil, nil // 返回一个空切片。
		}
		log.Printf("error getting data from redis: %v", err)
		return nil, err
	}

	// 尝试将JSON字符串反序列化回ThreatSource对象的切片
	var dataEntry ThreatDataEntry
	err = json.Unmarshal(serializedData, &dataEntry)
	if err != nil {
		// 解析成功，返回解析后的ThreatSource切片
		return nil, err
	}
	return &dataEntry, nil
}

// 写入IP黑名单
func WriteBlockIP(ip string) error {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库5（DB5）
	if _, err := redisConn.Do("SELECT", 5); err != nil {
		return err
	}
	// 将序列化后的数据存储到Redis
	if _, err := redisConn.Do("SET", ip, "blocked"); err != nil {
		log.Println("set redis error:", err)
		return err
	}
	// 设置过期时间
	s, err := ReadSysConfig()
	if err != nil {
		return err
	}
	if _, err := redisConn.Do("EXPIRE", ip, s.BanDuration); err != nil {
		return err
	}

	return nil
}

// 读取IP黑名单
func ReadBlockIPs() ([]string, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库5（DB5）
	if _, err := redisConn.Do("SELECT", 5); err != nil {
		return nil, err
	}
	// 获取所有键
	keys, err := redis.Strings(redisConn.Do("KEYS", "*"))
	if err != nil {
		log.Println("Error retrieving keys from Redis:", err)
		return nil, err
	}

	blockedIPs := []string{}
	for _, key := range keys {
		value, err := redis.String(redisConn.Do("GET", key))
		if err != nil {
			log.Println("Error getting value from Redis:", err)
			continue // 跳过有错误的键
		}
		if value == "blocked" {
			blockedIPs = append(blockedIPs, key)
		}
	}

	return blockedIPs, nil
}

// 写入攻击统计
func WriteAttackCount(ip string) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库4（DB4）
	if _, err := redisConn.Do("SELECT", 4); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 使用 INCR 增加 IP 计数器
	if _, err := redisConn.Do("INCR", ip); err != nil {
		log.Println("Failed to increment IP request count in Redis:", err)
		return
	}

	// 检查键的过期时间
	ttl, err := redis.Int(redisConn.Do("TTL", ip))
	if err != nil {
		log.Println("Failed to get TTL for IP:", err)
		return
	}

	// 如果没有设置过期时间（新键），设置过期时间为60秒
	if ttl == -1 {
		if _, err := redisConn.Do("EXPIRE", ip, 60); err != nil {
			log.Println("Failed to set expiration for IP request count in Redis:", err)
		}
	}
}

// 读取攻击统计
func ReadAttackCount(ip string) (int, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	if _, err := redisConn.Do("SELECT", 4); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 获取 IP 对应的计数器值
	attackCount, err := redis.Int(redisConn.Do("GET", ip))
	if err == redis.ErrNil {
		// 如果计数器不存在，则返回 0
		return 0, err
	}
	if err != nil {
		// 如果发生其他错误，记录日志并返回
		log.Println("Failed to get IP request count from Redis:", err)
		return 0, err
	}
	return attackCount, nil
}

// 写入国家位置
func WriteLocation(dataEntry *ThreatDataEntry) {
	redisConn := redisPool.Get()
	if redisConn == nil {
		log.Fatal("Failed to get Redis connection")
		return
	}
	defer redisConn.Close()

	// 选择数据库2（DB2）
	if _, err := redisConn.Do("SELECT", 2); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 检查 dataEntry 是否为 nil
	if dataEntry == nil {
		log.Fatal("dataEntry is nil")
		return
	}

	// 使用 HINCRBY 增加国家对应的计数器
	country := dataEntry.Basic.Location.Country
	if country == "" {
		log.Fatal("Country is empty")
		return
	}

	if _, err := redisConn.Do("HINCRBY", "location", country, 1); err != nil {
		log.Printf("Failed to increment count for country %s in Redis: %v", country, err)
		return
	}

	log.Printf("Successfully incremented count for country %s", country)
}

func WriteAiAttackCount(ip string) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	// 选择数据库4（DB4）
	if _, err := redisConn.Do("SELECT", 6); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 使用 INCR 增加 IP 计数器
	if _, err := redisConn.Do("INCR", ip); err != nil {
		log.Println("Failed to increment IP request count in Redis:", err)
		return
	}

	// 检查键的过期时间
	ttl, err := redis.Int(redisConn.Do("TTL", ip))
	if err != nil {
		log.Println("Failed to get TTL for IP:", err)
		return
	}

	// 如果没有设置过期时间（新键），设置过期时间为60秒
	if ttl == -1 {
		if _, err := redisConn.Do("EXPIRE", ip, 60); err != nil {
			log.Println("Failed to set expiration for IP request count in Redis:", err)
		}
	}
}

func ReadAiAttackCount(ip string) (int, error) {
	redisConn := redisPool.Get()
	defer redisConn.Close()

	if _, err := redisConn.Do("SELECT", 6); err != nil {
		log.Fatal("Failed to select Redis database:", err)
	}

	// 获取 IP 对应的计数器值
	attackCount, err := redis.Int(redisConn.Do("GET", ip))
	if err == redis.ErrNil {
		// 如果计数器不存在，则返回 0
		return 0, err
	}
	if err != nil {
		// 如果发生其他错误，记录日志并返回
		log.Println("Failed to get IP request count from Redis:", err)
		return 0, err
	}
	return attackCount, nil
}
