import requests
import random
import time
from datetime import datetime, timedelta

# 扩展的攻击向量
sql_injections = ["' OR '1'='1",
                  "' DROP TABLE users; --",
                  '2 and 1=2',
                  "admin'and(select*from(select+sleep(3))a/**/union/**/select+1)='",
                  "${987581318+821613195}",
                  "/*1*/{{894643765+956323033}}",
                  "admin$(expr 962935251 + 929380135)",
                  "expr 806611221 + 997466205"]
xss_attacks = ["<script>alert('XSS')</script>",
               "<img src=x onerror=alert('XSS')>",
               '<script>alert("xss")</script>',
               "<SCRIPT SRC=http://127.0.0.1/xss.js></SCRIPT>",
               'IMG SRC="javascript:alert(\'XSS\');">',
               "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
               "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
               "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>"]
normal_request = ['1', '2', '3', 'admin', 'xh', 'asd', 'sdaf', 'sdaf']
# 常见的User-Agent列表
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",  # Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",  # Safari
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",  # IE
    "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1",  # iPhone Safari
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",  # Googlebot
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",  # Baidu Spider
    'Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html)'
    'sqlmap/1.5.6.3#dev (http://sqlmap.org)'
    # 更多User-Agent，包括其他浏览器和扫描工具
]

# 目标URL
url = "http://your-waf-protected-site.com"

# 结束时间设置为12小时后
end_time = datetime.now() + timedelta(hours=12)

# 统计数据
total_requests = 0
blocked_requests = 0
successful_requests = 0
normal_request = 0
attack_request = 0

while datetime.now() < end_time:
    # 随机选择攻击类型
    attack_type = random.choice(['SQL', 'XSS', 'NORMAL'])
    if attack_type == "SQL":
        payload = random.choice(sql_injections)
        attack_request += 1
    elif attack_type == "XSS":
        payload = random.choice(xss_attacks)
        attack_request += 1
    else:
        payload = random.choice(normal_request)
        normal_request += 1
    
    # 随机选择请求方法和User-Agent
    headers = {'User-Agent': random.choice(user_agents)}
    if random.choice(['GET', 'POST']) == 'GET':
        response = requests.get(url, params=payload, headers=headers)
    else:
        response = requests.post(url, data=payload, headers=headers)
    
    total_requests += 1
    
    # 检查响应
    if "403" in response.text or response.status_code == 403:
        blocked_requests += 1
    else:
        successful_requests += 1
    
    # 每个请求之间暂停随机时间
    time.sleep(random.uniform(0.5, 2))

# 输出统计结果
print(f"Total Requests: {total_requests}")
print(f"Blocked Requests: {blocked_requests}")
print(f"Successful Requests: {successful_requests}")
print(f"Normal Requests: {normal_request}")
print(f"Attack Requests: {attack_request}")
