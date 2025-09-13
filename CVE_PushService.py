# coding=utf-8
import sys
import smtplib
import time
from email.mime.text import MIMEText
from email.header import Header

# 加载.env文件中的环境变量
from dotenv import load_dotenv
load_dotenv()

import requests
import json
import os
import gzip
import io
import sqlite3
import logging
import calendar
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta, UTC
from serverchan_sdk import sc_send

# 基本配置
SCKEY = os.getenv("SCKEY")
DINGTALK_WEBHOOK = os.getenv("DINGTALK_WEBHOOK")
DINGTALK_SECRET = os.getenv("DINGTALK_SECRET")  # 钉钉加签密钥
EMAIL_SMTP_SERVER = os.getenv("EMAIL_SMTP_SERVER")
# 更健壮地处理EMAIL_SMTP_PORT，避免空字符串转换错误
EMAIL_SMTP_PORT_VALUE = os.getenv("EMAIL_SMTP_PORT", "587")
EMAIL_SMTP_PORT = int(EMAIL_SMTP_PORT_VALUE) if EMAIL_SMTP_PORT_VALUE.strip() else 587
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

# 推送模式配置 (all, serverchan, dingtalk, email)
PUSH_MODE = os.getenv("PUSH_MODE", "dingtalk").lower()

DB_PATH = 'vulns.db'  # 数据库文件路径
LOG_FILE = 'cveflows.log'  # 日志文件前缀
DATA_DIR = 'data'  # 数据存储目录
CVSS_THRESHOLD = 7.0  # 只关注CVSS>=7.0的高危漏洞

# 日志配置
logger = logging.getLogger("CVEFlows")
logger.setLevel(logging.INFO)

# 控制台输出
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# 文件轮转输出：每天生成一个日志，保留 7 天
file_handler = TimedRotatingFileHandler(
    LOG_FILE, when="midnight", interval=1, backupCount=7, encoding="utf-8"
)
file_handler.setLevel(logging.INFO)

# 日志格式
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# 初始化数据库
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 检查表是否存在
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulns'")
    table_exists = c.fetchone() is not None
    
    if not table_exists:
        # 创建表（新表）
        c.execute('''CREATE TABLE IF NOT EXISTS vulns
                     (id TEXT PRIMARY KEY, 
                      published_date TEXT, 
                      cvss_score REAL, 
                      description TEXT, 
                      vector_string TEXT,
                      refs TEXT,
                      source TEXT,
                      tags TEXT)''')
    else:
        # 检查表是否有tags列
        c.execute("PRAGMA table_info(vulns)")
        columns = [column[1] for column in c.fetchall()]
        if 'tags' not in columns:
            # 添加tags列
            c.execute("ALTER TABLE vulns ADD COLUMN tags TEXT")
    
    conn.commit()
    conn.close()

# 获取当前年份
def get_current_year():
    return datetime.now().year

# 翻译函数（支持有道和Google翻译API容灾）
def translate(text):
    # 主翻译API：有道翻译
    def youdao_translate(text):
        url = 'https://aidemo.youdao.com/trans'
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                data = {"q": text, "from": "auto", "to": "zh-CHS"}
                resp = requests.post(url, data, timeout=15)
                if resp is not None and resp.status_code == 200:
                    respJson = resp.json()
                    if "translation" in respJson:
                        return "\n".join(str(i) for i in respJson["translation"])
                else:
                    logger.warning(f"有道翻译API返回非200状态码: {resp.status_code if resp else '无响应'}, 尝试第{retry_count+1}次重试...")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"有道翻译API连接错误: {str(e)}, 尝试第{retry_count+1}次重试...")
            except requests.exceptions.Timeout as e:
                logger.warning(f"有道翻译API请求超时: {str(e)}, 尝试第{retry_count+1}次重试...")
            except ValueError as e:
                logger.warning(f"有道翻译API返回格式错误: {str(e)}")
                break  # JSON解析错误不需要重试
            except Exception as e:
                logger.warning(f"有道翻译消息时发生错误: {str(e)}")
            
            retry_count += 1
            if retry_count <= max_retries:
                time.sleep(1)  # 重试间隔1秒
        
        return None  # 所有重试都失败时返回None
    
    # 备用翻译API：Google翻译
    def google_translate(text):
        url = 'https://translate.googleapis.com/translate_a/single'
        params = {
            'client': 'gtx',
            'sl': 'auto',  # 源语言自动检测
            'tl': 'zh-CN',  # 目标语言为中文
            'dt': 't',
            'q': text
        }
        
        try:
            resp = requests.get(url, params=params, timeout=15)
            if resp.status_code == 200:
                respJson = resp.json()
                if respJson and isinstance(respJson, list):
                    # Google翻译API返回的结构需要解析
                    translated_text = ''.join([item[0] for item in respJson[0] if item and item[0]])
                    return translated_text
        except Exception as e:
            logger.warning(f"Google翻译API错误: {str(e)}")
        
        return None  # 失败时返回None
    
    # 首先尝试使用有道翻译API
    logger.info("使用有道翻译API进行翻译...")
    translated_text = youdao_translate(text)
    
    # 如果有道翻译API失败，尝试使用Google翻译API
    if translated_text is None:
        logger.info("有道翻译API失败，尝试使用Google翻译API进行容灾...")
        translated_text = google_translate(text)
    
    # 如果所有翻译API都失败，返回原文
    if translated_text is None or translated_text.strip() == '':
        logger.warning("所有翻译API都失败，返回原文")
        return text
    
    return translated_text

# 从NVD获取CVE数据
def fetch_nvd_data(use_recent=True):
    if use_recent:
        url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz"
    else:
        year = get_current_year()
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

    try:
        logger.info(f"Fetching data from: {url}")
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status()

        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz_file:
            data = json.loads(gz_file.read().decode('utf-8'))
            return data.get('vulnerabilities', [])
    except Exception as e:
        logger.error(f"Failed to fetch NVD data: {str(e)}")
        return []

# 检查漏洞是否在最近24小时内发布
def is_recent(published_date_str):
    try:
        # 将发布日期转换为UTC时区感知的datetime对象
        published_dt = datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC)
        time_diff = datetime.now(UTC) - published_dt
        return time_diff.total_seconds() <= 24 * 3600
    except Exception as e:
        logger.error(f"Failed to parse date {published_date_str}: {str(e)}")
        return False

# 解析CVE条目，提取关键信息
def parse_cve_item(cve_item):
    try:
        cve_data = cve_item['cve']
        cve_id = cve_data.get('id', 'UNKNOWN')
        published_date = cve_data['published']

        if not is_recent(published_date):
            logger.debug(f"Skipping {cve_id} as it's not recent ({published_date})")
            return None

        description = next((desc['value'] for desc in cve_data.get('descriptions', [])
                               if desc.get('lang') == 'en'), "No description available")

        cvss_score = 0.0
        vector_string = "N/A"

        if 'metrics' in cve_data:
            if 'cvssMetricV31' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                vector_string = cvss_data.get('vectorString', "N/A")
            elif 'cvssMetricV30' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                vector_string = cvss_data.get('vectorString', "N/A")
            elif 'cvssMetricV2' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                vector_string = cvss_data.get('vectorString', "N/A")

        if cvss_score < CVSS_THRESHOLD:
            return None

        refs = "\n".join([ref.get('url', '') for ref in cve_data.get('references', [])][:3])

        # 提取漏洞分类标签
        tags = []
        if 'problemTypes' in cve_data:
            for problem_type in cve_data['problemTypes']:
                if 'descriptions' in problem_type:
                    for desc in problem_type['descriptions']:
                        if desc.get('lang') == 'en':
                            # 提取CWE信息
                            cwe_text = desc.get('value', '').strip()
                            if cwe_text.startswith('CWE-'):
                                cwe_id = cwe_text.split(' ', 1)[0]
                                tags.append(cwe_id)
                                
                                # 添加对应的中文标签
                                cwe_mapping = {
                                    'CWE-20': '输入验证不当',
                                    'CWE-78': '命令注入',
                                    'CWE-89': 'SQL注入',
                                    'CWE-352': '跨站请求伪造',
                                    'CWE-79': '跨站脚本',
                                    'CWE-434': '不安全文件上传',
                                    'CWE-287': '身份验证绕过',
                                    'CWE-22': '路径遍历',
                                    'CWE-362': '竞争条件',
                                    'CWE-476': '空指针解引用',
                                    'CWE-119': '缓冲区溢出',
                                    'CWE-120': '缓冲区溢出',
                                    'CWE-502': '反序列化漏洞',
                                    'CWE-269': '权限提升',
                                    'CWE-400': '资源耗尽',
                                    'CWE-770': '资源耗尽',
                                    'CWE-918': '服务器端请求伪造',
                                    'CWE-123': '写入错误',
                                    'CWE-134': '格式化字符串漏洞',
                                    'CWE-190': '整数溢出',
                                    'CWE-250': '特权提升',
                                    'CWE-306': '缺少身份验证',
                                    'CWE-319': '明文传输',
                                    'CWE-345': '验证不足',
                                    'CWE-359': '信息泄露',
                                    'CWE-416': '使用后释放',
                                    'CWE-426': '未受信任的搜索路径',
                                    'CWE-434': '不安全文件上传',
                                    'CWE-522': '凭证暴露',
                                    'CWE-523': '凭证暴露',
                                    'CWE-601': '开放重定向',
                                    'CWE-732': '权限配置错误',
                                    'CWE-862': '缺少授权',
                                    'CWE-863': '错误授权',
                                    'CWE-908': '未初始化变量',
                                    'CWE-917': '表达式注入',
                                    'CWE-922': '不安全存储'
                                }
                                if cwe_id in cwe_mapping:
                                    tags.append(cwe_mapping[cwe_id])
        
        # 根据CVSS评分添加严重性标签
        if cvss_score >= 9.0:
            tags.append('严重')
        elif cvss_score >= 7.0:
            tags.append('高危')
        
        # 去重并转换为字符串
        tags_str = ','.join(list(set(tags))) if tags else '未分类'

        return {
            'id': cve_id,
            'published_date': cve_data.get('published', 'N/A'),
            'cvss_score': cvss_score,
            'description': description,
            'vector_string': vector_string,
            'refs': refs,
            'source': 'NVD (National Vulnerability Database)',
            'tags': tags_str
        }
    except KeyError as e:
        logger.error(f"Error parsing CVE item: missing key {str(e)}")
        return None

# 检查是否是新漏洞
def is_new_vuln(vuln_info):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM vulns WHERE id=?", (vuln_info['id'],))
    exists = c.fetchone() is not None
    conn.close()
    return not exists

# 保存漏洞信息到数据库
def save_vuln(vuln_info):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # 检查数据库是否有tags列
        c.execute("PRAGMA table_info(vulns)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'tags' in columns:
            # 如果有tags列，插入包含tags的完整数据
            c.execute("INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (vuln_info['id'], vuln_info['published_date'], vuln_info['cvss_score'],
                       vuln_info['description'], vuln_info['vector_string'],
                       vuln_info['refs'], vuln_info['source'], vuln_info.get('tags', '未分类')))
        else:
            # 如果没有tags列，插入不包含tags的数据
            c.execute("INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (vuln_info['id'], vuln_info['published_date'], vuln_info['cvss_score'],
                       vuln_info['description'], vuln_info['vector_string'],
                       vuln_info['refs'], vuln_info['source']))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

# 生成通知内容
def generate_notification_content(vuln_info):
    # 在标题中添加严重程度标签（如果有）
    title = f"高危漏洞: {vuln_info['id']} ({vuln_info['cvss_score']})"
    if 'tags' in vuln_info and vuln_info['tags']:
        tags = vuln_info['tags'].split(',')
        # 检查是否有'严重'或'高危'标签
        for tag in tags:
            if tag in ['严重', '高危']:
                title = f"{tag}漏洞: {vuln_info['id']} ({vuln_info['cvss_score']})"
                break

    translated_description = translate(vuln_info['description'])

    # 在描述中添加标签信息
    tags_section = """
## 漏洞分类
{vuln_tags}
"""
    
    if 'tags' in vuln_info and vuln_info['tags'] and vuln_info['tags'] != '未分类':
        # 将逗号分隔的标签转换为列表并格式化显示
        tags_list = vuln_info['tags'].split(',')
        formatted_tags = "、".join(tags_list)
        tags_section = tags_section.format(vuln_tags=formatted_tags)
    else:
        tags_section = ""

    # 优化markdown格式，使其与daily.md风格一致
    desp = f"""
## 漏洞详情
**CVE ID**: {vuln_info['id']}
**发布时间**: {vuln_info['published_date']}
**CVSS分数**: {vuln_info['cvss_score']}
**攻击向量**: {vuln_info['vector_string']}

## 漏洞描述
{translated_description}

## 相关链接
{vuln_info['refs']}

## 来源
{vuln_info['source']}

{tags_section}

---
*本通知由 CVE Push Service 自动生成*
"""
    
    return title, desp

# 通过Server酱发送通知
def send_serverchan_notification(vuln_info):
    if not SCKEY:
        logger.warning("Server酱 SCKEY 未配置，跳过Server酱推送")
        return
        
    title, desp = generate_notification_content(vuln_info)
    
    try:
        response = sc_send(SCKEY, title, desp, {"tags": "漏洞警报"})
        logger.info(f"Server酱通知已发送: {vuln_info['id']}, 响应: {response}")
    except Exception as e:
        logger.error(f"Server酱通知发送失败: {str(e)}")

import time
import base64
import hmac
import hashlib

# 通过钉钉发送通知
def send_dingtalk_notification(vuln_info):
    if not DINGTALK_WEBHOOK:
        logger.warning("钉钉Webhook 未配置，跳过钉钉推送")
        return
        
    title, desp = generate_notification_content(vuln_info)
    
    # 钉钉消息格式
    data = {
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "text": desp
        }
    }
    
    try:
        headers = {'Content-Type': 'application/json'}
        webhook_url = DINGTALK_WEBHOOK
        
        # 如果配置了加签密钥，则生成签名
        if DINGTALK_SECRET:
            # 获取当前时间戳（毫秒级）
            timestamp = str(round(time.time() * 1000))
            # 拼接时间戳和密钥
            secret_enc = DINGTALK_SECRET.encode('utf-8')
            string_to_sign = '{}\n{}'.format(timestamp, DINGTALK_SECRET)
            string_to_sign_enc = string_to_sign.encode('utf-8')
            # 使用HmacSHA256算法计算签名
            hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
            # 对签名进行Base64编码
            sign = base64.b64encode(hmac_code).decode('utf-8')
            # 对Base64编码后的签名进行URL编码，修复签名不匹配问题
            import urllib.parse
            sign_encoded = urllib.parse.quote_plus(sign)
            # 将时间戳和签名添加到URL中
            if '?' in webhook_url:
                webhook_url = f"{webhook_url}&timestamp={timestamp}&sign={sign_encoded}"
            else:
                webhook_url = f"{webhook_url}?timestamp={timestamp}&sign={sign_encoded}"
            logger.info("已启用钉钉加签验证")
        
        response = requests.post(webhook_url, headers=headers, data=json.dumps(data), timeout=15)
        response_json = response.json()
        if response_json.get("errcode") == 0:
            logger.info(f"钉钉通知已发送: {vuln_info['id']}")
        else:
            logger.error(f"钉钉通知发送失败: {response_json.get('errmsg')}")
    except Exception as e:
        logger.error(f"钉钉通知发送异常: {str(e)}")

# 通过邮箱发送通知
def send_email_notification(vuln_info):
    if not all([EMAIL_SMTP_SERVER, EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_RECEIVER]):
        logger.warning("邮箱配置不完整，跳过邮箱推送")
        return
        
    title, desp = generate_notification_content(vuln_info)
    
    try:
        # 创建邮件内容
        message = MIMEText(desp, 'plain', 'utf-8')
        message['From'] = Header(EMAIL_USERNAME)
        message['To'] = Header(EMAIL_RECEIVER)
        message['Subject'] = Header(title)
        
        # 发送邮件
        server = smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT)
        server.starttls()  # 启用TLS加密
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USERNAME, [EMAIL_RECEIVER], message.as_string())
        server.quit()
        
        logger.info(f"邮件通知已发送: {vuln_info['id']} 到 {EMAIL_RECEIVER}")
    except Exception as e:
        logger.error(f"邮件通知发送失败: {str(e)}")

# 统一的通知入口
def send_notification(vuln_info):
    logger.info(f"使用推送模式: {PUSH_MODE}")
    
    # 根据推送模式选择推送方式
    if PUSH_MODE == 'all':
        # 调用所有配置了的推送方式
        send_serverchan_notification(vuln_info)
        send_dingtalk_notification(vuln_info)
        send_email_notification(vuln_info)
    elif PUSH_MODE == 'serverchan':
        # 只使用Server酱推送
        send_serverchan_notification(vuln_info)
    elif PUSH_MODE == 'dingtalk':
        # 只使用钉钉推送
        send_dingtalk_notification(vuln_info)
    elif PUSH_MODE == 'email':
        # 只使用邮件推送
        send_email_notification(vuln_info)
    else:
        logger.warning(f"未知的推送模式: {PUSH_MODE}，将使用所有推送方式")
        send_serverchan_notification(vuln_info)
        send_dingtalk_notification(vuln_info)
        send_email_notification(vuln_info)

# 获取当天日期的漏洞信息
def get_today_vulnerabilities():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 计算今天的日期范围（UTC时间）
    today = datetime.now(UTC).date()
    tomorrow = today + timedelta(days=1)
    
    # 格式化日期字符串
    today_str = today.strftime('%Y-%m-%d')
    tomorrow_str = tomorrow.strftime('%Y-%m-%d')
    
    # 检查数据库是否有tags列
    c.execute("PRAGMA table_info(vulns)")
    columns = [column[1] for column in c.fetchall()]
    
    # 根据是否有tags列选择不同的查询语句
    if 'tags' in columns:
        c.execute("""
            SELECT id, published_date, cvss_score, description, vector_string, refs, source, tags 
            FROM vulns 
            WHERE published_date >= ? AND published_date < ?
            ORDER BY cvss_score DESC
        """, (today_str, tomorrow_str))
    else:
        c.execute("""
            SELECT id, published_date, cvss_score, description, vector_string, refs, source 
            FROM vulns 
            WHERE published_date >= ? AND published_date < ?
            ORDER BY cvss_score DESC
        """, (today_str, tomorrow_str))
    
    vulns = []
    for row in c.fetchall():
        vuln_dict = {
            'id': row[0],
            'published_date': row[1],
            'cvss_score': row[2],
            'description': row[3],
            'vector_string': row[4],
            'refs': row[5],
            'source': row[6]
        }
        # 如果查询结果包含tags列，则添加tags字段
        if len(row) > 7:
            vuln_dict['tags'] = row[7]
        
        vulns.append(vuln_dict)
    
    conn.close()
    return vulns

# 获取周数和日期格式
def get_week_date_format(date=None):
    if date is None:
        date = datetime.now(UTC).date()
    
    # 获取年份
    year = date.strftime('%Y')
    
    # 获取周数（W格式）
    week_number = date.strftime('%W')
    
    # 获取月日格式（MMDD）
    mmdd = date.strftime('%m%d')
    
    return f"{year}/W{week_number}-{mmdd}"

# 创建目录结构
def create_directory_structure(dir_path):
    # 使用exist_ok=True参数，确保即使父目录不存在也能正确创建，且目录已存在时不会抛出异常
    os.makedirs(dir_path, exist_ok=True)
    logger.info(f"创建或确认目录存在: {dir_path}")

# 生成漏洞报告markdown
def generate_vulnerability_report(vulns):
    today = datetime.now(UTC).strftime('%Y年%m月%d日')
    report_date = datetime.now(UTC).strftime('%Y-%m-%d')
    
    markdown_content = f"""
# {today} 高危漏洞日报

## 概述
- 总漏洞数量: {len(vulns)}
- 最高CVSS评分: {max([v['cvss_score'] for v in vulns]) if vulns else 0}
- 统计时间: {report_date} (UTC)

"""
    
    # 按CVSS分数排序并分组
    critical_vulns = [v for v in vulns if v['cvss_score'] >= 9.0]
    high_vulns = [v for v in vulns if 7.0 <= v['cvss_score'] < 9.0]
    
    if critical_vulns:
        markdown_content += f"\n## 严重漏洞 (CVSS ≥ 9.0) [共{len(critical_vulns)}个]\n\n"
        for vuln in critical_vulns:
            markdown_content += generate_vuln_markdown(vuln)
    
    if high_vulns:
        markdown_content += f"\n## 高危漏洞 (7.0 ≤ CVSS < 9.0) [共{len(high_vulns)}个]\n\n"
        for vuln in high_vulns:
            markdown_content += generate_vuln_markdown(vuln)
    
    # 添加报告尾部
    markdown_content += f"""

## 数据来源
- NVD (National Vulnerability Database)

---
*本报告由 CVE Push Service 自动生成*"
"""
    
    return markdown_content

# 生成单个漏洞的markdown
def generate_vuln_markdown(vuln_info):
    translated_description = translate(vuln_info['description'])
    
    # 准备标签部分的markdown
    tags_section = ""
    if 'tags' in vuln_info and vuln_info['tags'] and vuln_info['tags'] != '未分类':
        tags_list = vuln_info['tags'].split(',')
        formatted_tags = "、".join(tags_list)
        tags_section = f"\n**漏洞分类**: {formatted_tags}\n"
    
    return f"""
### {vuln_info['id']} - CVSS: {vuln_info['cvss_score']}

**发布时间**: {vuln_info['published_date']}
**攻击向量**: {vuln_info['vector_string']}{tags_section}

#### 漏洞描述
{translated_description}

#### 相关链接
{vuln_info['refs']}

"""

# 保存漏洞报告为markdown文件
def save_vulnerability_report():
    vulns = get_today_vulnerabilities()
    
    if not vulns:
        logger.info("今天没有新的漏洞需要生成报告")
        return
    
    # 生成报告内容
    markdown_content = generate_vulnerability_report(vulns)
    
    # 获取日期格式并创建目录
    date_format = get_week_date_format()
    dir_path = os.path.join(DATA_DIR, date_format)
    create_directory_structure(dir_path)
    
    # 保存为文件
    file_path = os.path.join(dir_path, 'daily.md')
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        logger.info(f"漏洞报告已保存到: {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"保存漏洞报告失败: {str(e)}")
        return None


def main():
    logger.info("Starting CVE monitoring...")

    init_db()

    logger.info("Fetching recent CVE data...")
    cve_items = fetch_nvd_data(use_recent=True)

    if not cve_items:
        logger.warning("Failed to fetch recent data, trying full year data...")
        cve_items = fetch_nvd_data(use_recent=False)

    if not cve_items:
        logger.error("Failed to fetch any CVE data. Exiting.")
        return 0

    logger.info(f"Found {len(cve_items)} CVE items")

    new_vulns = 0
    new_ids = []
    for item in cve_items:
        vuln_info = parse_cve_item(item)
        if vuln_info and is_new_vuln(vuln_info):
            logger.info(f"[INFO] New high-risk vulnerability found: {vuln_info['id']}")
            save_vuln(vuln_info)
            send_notification(vuln_info)
            new_vulns += 1
            new_ids.append(vuln_info['id'])

    logger.info(f"[INFO] Monitoring completed. Found {new_vulns} new vulnerabilities.")

    if new_vulns > 0:
        with open("new_vulns.flag", "w") as f:
            f.write(f"{new_vulns}\n")
            f.write("\n".join(new_ids))

    # 生成并保存每日漏洞报告
    save_vulnerability_report()

    return 0

if __name__ == '__main__':
    sys.exit(main())
