# CVE_PushService

## 项目简介

CVE_PushService 是一个面向网络安全从业者的高危漏洞实时情报推送工具，自动拉取 NVD 最新漏洞数据，筛选 CVSS ≥ 7.0 的高危漏洞，并通过钉钉、邮件等推送渠道推送漏洞信息，帮助您在应急响应等场合中抢占先机。

## 项目架构

本项目采用模块化架构设计，将功能拆分为多个独立且可复用的模块，便于维护和扩展。

```
src/
├── core/             # 核心功能模块
│   ├── cve_collector.py  # CVE信息收集器
│   └── cve_processor.py  # CVE信息处理器
├── monitor/          # 监控模块
│   └── poc_monitor.py    # POC监控器
├── utils/            # 工具模块
│   ├── db_manager.py     # 数据库管理
│   ├── date_helper.py    # 日期处理
│   ├── file_helper.py    # 文件操作
│   ├── cache_helper.py   # 缓存管理
│   ├── translation_helper.py  # 翻译功能
│   ├── security_utils.py      # 安全工具
│   └── notification_helper.py # 通知发送
└── config/           # 配置模块
    ├── settings.py       # 设置管理
    └── logging_config.py # 日志配置
```

## 功能特点

- **实时监控**：自动获取 NVD 最新漏洞情报
- **高危筛选**：仅推送 CVSS ≥ 7.0 的高风险漏洞
- **智能翻译**：集成有道翻译 API，支持漏洞描述中文化，新增Google翻译API容灾机制，确保翻译服务稳定性
- **多渠道推送**：支持通过 Server酱、钉钉、邮箱多种方式推送漏洞信息
- **报告生成**：自动生成每日漏洞报告，按年/周-日期格式归档存储
- **POC监控**：监控高危漏洞的POC/EXP情况
- **去重存储**：使用数据库存储，避免重复推送
- **日志管理**：支持日志文件轮转，方便审计与追溯
- **自动化运行**：支持 GitHub Actions 定时任务

## 快速开始

### 环境准备

1. **安装 Python**：项目需要 Python 3.6 或更高版本

2. **安装依赖**：
   ```bash
   pip install -r requirements.txt
   ```

3. **配置环境变量**：
   - 复制 `.env.example` 并重命名为 `.env`
   - 编辑 `.env` 文件，填写您的配置信息

### 使用方法

#### 命令行接口

项目提供了多种命令行工具，方便您根据需要执行不同的操作：

```bash
# 处理单个CVE
python main.py cve CVE-2023-1234

# 处理当日漏洞
python main.py daily

# 启动持续监控服务
python main.py monitor

# 生成每日报告
python main.py report
# 生成指定日期的报告
python main.py report --date 2023-09-13
```

#### 本地测试

1. 确保已经配置了`.env`文件

2. 执行以下命令运行程序：
   ```bash
   python main.py daily
   ```

3. 检查输出结果和生成的报告

## 配置说明

### 环境变量配置

项目使用 `.env` 文件管理配置，主要配置项包括：

- **Server酱配置**：`SCKEY` - Server酱SendKey
- **钉钉配置**：`DINGTALK_WEBHOOK` - 钉钉机器人Webhook地址，`DINGTALK_SECRET` - 钉钉加签密钥
- **邮箱配置**：`EMAIL_SMTP_SERVER`、`EMAIL_SMTP_PORT`、`EMAIL_USERNAME`、`EMAIL_PASSWORD`、`EMAIL_RECEIVER`
- **推送模式**：`PUSH_MODE` - 可选值：all、serverchan、dingtalk、email
- **其他配置**：日志级别、缓存设置、数据库路径等

### 配置文件

项目使用 `config/config.yaml` 文件管理POC监控的数据源配置，您可以根据需要添加或修改数据源。

## 报告存储

项目会自动生成漏洞报告，并按照以下目录结构存储：

- **存在POC的漏洞报告**：`pocData/YYYY/W-WWDD/daily.md`
- **不存在POC的漏洞报告**：`data/YYYY/W-WWDD/daily.md`

其中：
- `YYYY`：年份，例如：2025
- `WW`：周数，例如：37
- `DD`：日期，例如：13

## GitHub Actions 自动化

本项目支持通过 GitHub Actions 实现自动化运行：

1. 在仓库的 `Settings` → `Secrets` 中配置所需的环境变量
2. 启用 `.github/workflows/AutoCVE.yml` 工作流
3. 工作流将每天自动运行，并通过配置的方式推送通知

## 常见问题

### 无法获取 NVD 数据
- 检查网络连接是否正常
- 确认 URL 是否可访问
- 查看日志文件中的错误信息

### 通知推送失败
- 检查环境变量是否正确配置
- 验证 Server酱 SendKey、钉钉 Webhook 或邮箱配置是否有效
- 查看日志中的具体错误信息

### 数据库操作错误
- 确保您有文件写入权限
- 检查数据库文件是否被其他进程占用

## 开发指南

如果您想参与项目开发或进行自定义修改，请遵循以下原则：

1. 遵循模块化设计原则
2. 保持代码风格一致
3. 添加适当的注释和文档
4. 进行充分的测试

## 更新日志

- 2025-09-13 🔄 增强翻译功能：新增Google翻译API作为容灾备份
- 2025-09-13 🐛 修复环境变量处理问题：增强EMAIL_SMTP_PORT的类型转换逻辑
- 2025-09-13 🛠️ 优化GitHub Actions工作流：添加数据库下载失败的fallback机制
- 2025-09-13 ✅ 新增漏洞分类标签功能：自动提取CWE信息并转换为中文标签
- 2025-09-13 🔐 新增钉钉加签功能：支持配置DINGTALK_SECRET环境变量
- 2025-09-13 🔧 重构项目架构：采用模块化设计，提高代码可维护性

## 致谢

- 感谢 [kiang70](https://github.com/kiang70/Github-Monitor/)、[Kira-Pgr](https://github.com/Kira-Pgr/Github-CVE-Listener) 两位师傅提供思路
- 感谢 [Server酱3](https://sc3.ft07.com/) 提供稳定的消息推送服务
- 感谢 [NVD](https://nvd.nist.gov/) 提供权威的漏洞情报源
- 翻译由 **有道开放平台**、**Google translator** 提供