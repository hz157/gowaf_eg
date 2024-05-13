package gowaf

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var mysqlPool *sql.DB
var mysqlPoolOnce sync.Once

// MySQLTool 包含了连接MySQL数据库所需的信息和方法
type MySQLTool struct{}

// NewMySQLTool 创建一个新的MySQLTool实例
func NewMySQLTool() *MySQLTool {
	return &MySQLTool{}
}

func MysqlInit(MysqlAddr, MysqlDB, MysqlUser, MysqlPwd string, MysqlPort int) {
	mysqlPoolOnce.Do(func() {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", MysqlUser, MysqlPwd, MysqlAddr, MysqlPort, MysqlDB)
		dbInstance, err := sql.Open("mysql", dsn)
		if err != nil {
			panic(err)
		}

		if err := dbInstance.Ping(); err != nil {
			panic(err)
		}

		mysqlPool = dbInstance
	})
}

// InsertLog 插入日志到eg_log表
func InsertEgLog(level, location, message string) error {
	// 插入日志
	query := "INSERT INTO eg_log (level, location, message) VALUES (?, ?, ?)"
	_, err := mysqlPool.Exec(query, level, location, message)
	// 报错返回
	if err != nil {
		return err
	}
	return nil
}

// 获取数据库中存放的waf规则
func GetWafRule() ([]string, error) {
	// 规则数组
	var rules []string

	// SQL查询云居
	rows, err := mysqlPool.Query("SELECT * FROM eg_rule")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 数据库结构体
	for rows.Next() {
		var (
			id       int
			ruleType string
			status   string
			ruleName string
			desc     string
			reg      string
			custom   int
			datetime string
		)

		// 检索数据库中返回的数据
		err := rows.Scan(&id, &ruleType, &status, &ruleName, &desc, &reg, &custom, &datetime)
		if err != nil {
			return nil, err
		}
		// 构造规则体
		ruleStr := fmt.Sprintf("{\"type\": %q, \"status\": %q, \"rule_name\": %q, \"desc\": %q, \"reg\": [%s]}",
			ruleType, status, ruleName, desc, reg)
		// 添加倒规则数组中
		rules = append(rules, ruleStr)
	}

	// 报错返回
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 返回规则数组
	return rules, nil
}

func InsertEgAttackRecord(req *http.Request, uuid, domain, ruleName, ruleDesc string) error {
	// 将 Request 的 Header 转换为 JSON 字符串
	headerBytes, err := json.Marshal(req.Header)
	if err != nil {
		return err
	}
	header := string(headerBytes)

	// 将 Request 的 Body 转换为字符串
	bodyBytes := new(bytes.Buffer)
	bodyBytes.ReadFrom(req.Body)
	body := bodyBytes.String()

	// 获取当前时间并转换为字符串
	datetime := time.Now().Format("2006-01-02 15:04:05")

	query := `INSERT INTO eg_attack_record 
		(uuid, domain, method, url, proto, header, body, host, remoteAddr, rule_name, rule_desc, datetime) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = mysqlPool.Exec(query, uuid, domain, req.Method, req.URL.String(), req.Proto, header, body, req.Host, req.RemoteAddr, ruleName, ruleDesc, datetime)
	if err != nil {
		log.Println("Insert Mysql Error: ", err)
		return err
	}
	return nil
}

func InsertEgAIAttackRecord(req *WafHttpRequest, uuid, domain, ruleName, ruleDesc string) error {
	// 获取当前时间并转换为字符串
	datetime := time.Now().Format("2006-01-02 15:04:05")

	query := `INSERT INTO eg_attack_record 
		(uuid, domain, method, url, proto, header, body, host, remoteAddr, rule_name, rule_desc, datetime) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := mysqlPool.Exec(query, uuid, domain, req.Method, req.Url, req.Proto, fmt.Sprintf("%v", req.Header), req.Body, req.Host, req.RemoteAddr, ruleName, ruleDesc, datetime)
	if err != nil {
		log.Println("Insert Mysql Error: ", err)
		return err
	}
	return nil
}

func GetBlockIP() ([]string, error) {
	// 规则数组
	var ipList []string

	// SQL查询云居
	rows, err := mysqlPool.Query("SELECT * FROM eg_block_ip where status = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 数据库结构体
	for rows.Next() {
		var (
			id       int
			ip       string
			user     int
			status   int
			datetime string
		)

		// 检索数据库中返回的数据
		err := rows.Scan(&id, &ip, &user, &status, &datetime)
		if err != nil {
			return nil, err
		}
		if status == 1 {
			// 添加倒规则数组中
			ipList = append(ipList, ip)
		}
	}

	// 报错返回
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 返回规则数组
	return ipList, nil
}

func GetWhiteIP() ([]string, error) {
	// 规则数组
	var ipList []string

	// SQL查询云居
	rows, err := mysqlPool.Query("SELECT * FROM eg_white_ip")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 数据库结构体
	for rows.Next() {
		var (
			id       int
			ip       string
			user     int
			datetime string
		)

		// 检索数据库中返回的数据
		err := rows.Scan(&id, &ip, &user, &datetime)
		if err != nil {
			return nil, err
		}
	}

	// 报错返回
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 返回规则数组
	return ipList, nil
}
