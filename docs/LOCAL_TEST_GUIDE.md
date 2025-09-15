# CVE_Push 本地测试指南

本指南将帮助您在本地环境中测试和运行 CVE_Push 项目。

## 📁 项目目录结构

项目采用以下目录结构组织代码和资源：
- **docs/**: 存放项目文档，包括使用说明和测试指南
- **config/**: 存放配置文件
- **logs/**: 存放日志文件
- **data/**: 存放漏洞数据和报告
- **utils/**: 存放工具函数和公共模块
- **CVE_PushService.py**: 核心服务程序
- **poc_monitor.py**: POC监控程序

## 📋 环境准备

### 1. 安装 Python

项目需要 Python 3.6 或更高版本。请确保您的系统已安装 Python。

```bash
# 检查 Python 版本
python --version
```

### 2. 安装依赖包

项目使用了以下依赖包：
- requests
- serverchan_sdk
- sqlite3 (Python 内置)

使用 pip 安装所需依赖：

```bash
pip install requests serverchan_sdk python-dotenv
```

## ⚙️ 配置环境变量

在本地测试时，您需要配置以下环境变量，这些变量与 GitHub Secrets 中配置的相同。有两种配置方式：使用.env文件（推荐）或直接在命令行设置。

### 📁 使用 .env 文件（推荐）

使用.env文件是管理环境变量的更便捷方式，特别适合本地开发和测试。

#### 1. 创建 .env 文件

在项目根目录创建一个名为 `.env` 的文件，添加以下内容：

```env
# Server酱配置
SCKEY=您的Server酱SendKey

# 钉钉配置
DINGTALK_WEBHOOK=您的钉钉Webhook地址
# 钉钉加签密钥（可选）
# 如果您的钉钉机器人启用了加签功能，请填写此密钥
# DINGTALK_SECRET=您的钉钉加签密钥

# 邮箱配置
EMAIL_SMTP_SERVER=您的SMTP服务器地址
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=您的发件人邮箱
EMAIL_PASSWORD=您的邮箱密码或授权码
EMAIL_RECEIVER=收件人邮箱地址

# 推送模式配置（可选）
# 可选值：all - 所有推送方式, serverchan - Server酱, dingtalk - 钉钉, email - 邮件
# 默认值：all
PUSH_MODE=all
```

#### 2. 修改代码加载 .env 文件

需要修改 `CVE_PushService.py` 文件，在文件开头添加加载.env文件的代码：

```python
# 在文件顶部导入dotenv模块
from dotenv import load_dotenv

# 加载.env文件中的环境变量
load_dotenv()
```

### Windows 命令行配置方法

如果您不想使用.env文件，可以在命令提示符中运行：

```cmd
set SCKEY=您的Server酱SendKey
set DINGTALK_WEBHOOK=您的钉钉Webhook地址
# 可选：设置钉钉加签密钥
# set DINGTALK_SECRET=您的钉钉加签密钥
set EMAIL_SMTP_SERVER=您的SMTP服务器地址
set EMAIL_SMTP_PORT=587
set EMAIL_USERNAME=您的发件人邮箱
set EMAIL_PASSWORD=您的邮箱密码或授权码
set EMAIL_RECEIVER=收件人邮箱地址
# 可选：设置推送模式（all/serverchan/dingtalk/email）
set PUSH_MODE=all
```

### Linux/Mac 命令行配置方法

在终端中运行：

```bash
export SCKEY=您的Server酱SendKey
export DINGTALK_WEBHOOK=您的钉钉Webhook地址
# 可选：设置钉钉加签密钥
# export DINGTALK_SECRET=您的钉钉加签密钥
export EMAIL_SMTP_SERVER=您的SMTP服务器地址
export EMAIL_SMTP_PORT=587
export EMAIL_USERNAME=您的发件人邮箱
export EMAIL_PASSWORD=您的邮箱密码或授权码
export EMAIL_RECEIVER=收件人邮箱地址
# 可选：设置推送模式（all/serverchan/dingtalk/email）
export PUSH_MODE=all
```

## 🚀 本地运行测试

### 1. 直接运行主脚本

在项目目录中执行：

```bash
python CVE_PushService.py
```

脚本将执行以下操作：
- 初始化数据库（如果不存在）
- 从 NVD 获取最近的漏洞数据
- 筛选 CVSS ≥ 7.0 的高危漏洞
- 检查是否为新漏洞（通过本地数据库）
- 发送通知（根据配置的推送方式）
- 生成并保存每日漏洞报告

### 2. 查看输出和日志

- 控制台输出：实时显示脚本执行状态和发现的漏洞
- 日志文件：`cveflows.log`，包含详细的执行记录
- 数据库文件：`vulns.db`，存储已发现的漏洞信息
- 报告文件：保存在 `data/YYYY/W-WWDD/` 目录下的 `daily.md`

## 🧪 测试技巧

### 1. 测试特定功能

如果您只想测试特定功能，可以修改代码或创建测试脚本。例如：

```python
# 测试翻译功能
from CVE_PushService import translate
print(translate("This is a test"))

# 测试报告生成功能
from CVE_PushService import save_vulnerability_report
save_vulnerability_report()
```

### 2. 使用测试标志文件

脚本运行后会生成 `new_vulns.flag` 文件，记录发现的新漏洞数量和ID。您可以查看此文件了解执行结果。

### 3. 清空数据库重新测试

如果需要重新开始测试，可以删除 `vulns.db` 文件，脚本将重新创建数据库并重新推送所有符合条件的漏洞。

## 🔍 常见问题排查

### 1. 无法获取 NVD 数据

- 检查网络连接是否正常
- 确认 URL 是否可访问
- 查看日志文件中的错误信息

### 2. 通知推送失败

- 检查环境变量是否正确配置
- 验证 Server酱 SendKey、钉钉 Webhook 或邮箱配置是否有效
- 查看日志中的具体错误信息

### 3. 数据库操作错误

- 确保您有文件写入权限
- 检查 `vulns.db` 文件是否被其他进程占用

## 💡 调试模式

您可以修改代码中的日志级别，获取更详细的调试信息：

```python
# 将日志级别从 INFO 改为 DEBUG
logger.setLevel(logging.DEBUG)
file_handler.setLevel(logging.DEBUG)
```

## 📝 注意事项

- 本地测试时，系统会首先使用有道翻译 API，如有失败会自动切换到Google翻译API作为备份
- 如果您不需要某种推送方式，可以不配置相应的环境变量
- 本地运行时，生成的报告将保存在项目目录下的 `data` 文件夹中
- 测试完成后，建议删除临时配置的敏感信息（如邮箱密码等）

## 📄 创建 requirements.txt

为了方便依赖管理，您可以在项目根目录创建一个 `requirements.txt` 文件：

```
requests
serverchan_sdk
python-dotenv
```

这样就可以使用 `pip install -r requirements.txt` 一键安装所有依赖。

---

祝您测试顺利！如果有任何问题，请参考代码中的日志输出或提交 issue。