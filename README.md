# 🔥 CVE Push | 自动化高危漏洞情报推送

<p align="center">

  <img src="https://img.shields.io/github/stars/adminlove520/cvePush?color=yellow&logo=riseup&logoColor=yellow&style=flat-square"></a>
  <img src="https://img.shields.io/github/forks/adminlove520/cvePush?color=purple&style=flat-square"></a>
  <img src="https://img.shields.io/badge/cvePush-blue?logo=datadog" alt="CVE Monitor">

</p>

> ⚡ 面向网络安全从业者的 **高危漏洞实时情报推送工具**  
> 自动拉取 NVD 最新漏洞数据，筛选 **CVSS ≥ 7.0** 的高危漏洞，并通过钉钉、邮件等推送渠道推送漏洞信息，帮助您在应急响应等场合中抢占先机。  

---

## 🚀 功能亮点

- ✅ **实时监控**：自动获取 [NVD](https://nvd.nist.gov/) 最新漏洞情报  
- ✅ **高危筛选**：仅推送 **CVSS ≥ 7.0** 的高风险漏洞  
- ✅ **智能翻译**：集成有道翻译 API，支持漏洞描述中文化，新增Google翻译API容灾机制，确保翻译服务稳定性  
- ✅ **多渠道推送**：支持通过 Server酱、钉钉、邮箱多种方式推送漏洞信息  
- ✅ **报告生成**：自动生成每日漏洞报告，按年/周-日期格式归档存储  
- ✅ **去重存储**：使用 Artifact 存储数据库，避免重复推送  
- ✅ **日志管理**：支持日志文件轮转，方便审计与追溯  
- ✅ **自动化运行**：支持 GitHub Actions 定时任务，方便省心，0 运维成本

---

## 🛠️ 使用方法

### 本地测试（可选）

如果您想在本地环境中测试和运行该项目，可以参考以下步骤：

1. **环境变量配置**：
   - 项目根目录提供了 `.env.example` 文件，包含所有需要的环境变量配置示例
   - 将 `.env.example` 文件复制并重命名为 `.env`
   - 编辑 `.env` 文件，填写您的实际配置信息
   - **注意**：`.env` 文件包含敏感信息，请确保它已添加到 `.gitignore` 中

2. **安装依赖**：
   ```bash
   pip install -r requirements.txt
   ```

3. **运行程序**：
   ```bash
   python CVE_PushService.py
   ```

详细的本地测试指南，请参阅项目根目录下的 `LOCAL_TEST_GUIDE.md` 文件。

---

### 1. 准备工作
看（[README.md](./README.md) ）

### 2. 配置推送方式

本仓库已内置 GitHub Actions 工作流（[AutoCVE.yml](./workflows/AutoCVE.yml) ）。
你可以在仓库 Settings → Secrets 中配置以下变量（根据你需要的推送方式选择配置）：

**Server酱推送配置（原功能）：**
- SCKEY : 你注册的 Server酱3 SendKey（注意！前后不要有空格回车）

**钉钉推送配置：**
- DINGTALK_WEBHOOK : 钉钉机器人的Webhook地址
- DINGTALK_SECRET : 钉钉机器人的加签密钥（可选，如启用加签功能）

**邮箱推送配置：**
- EMAIL_SMTP_SERVER : SMTP服务器地址（例如：smtp.qq.com）
- EMAIL_SMTP_PORT : SMTP服务器端口（默认：587）
- EMAIL_USERNAME : 发件人邮箱地址
- EMAIL_PASSWORD : 发件人邮箱密码/授权码
- EMAIL_RECEIVER : 收件人邮箱地址


### 3. GitHub Actions 自动化运行

- 点击仓库顶部的 `Actions` 标签页进入工作流页面，首次使用需点击 `I understand my workflow` 按钮确认启用工作流
- 页面自动刷新后，左侧菜单会出现 `Auto CVE Push Service` 工作流选项
- 点击该工作流，然后点击页面中的 `Enable Workflow` 按钮启用自动运行
- 启用后，您可以通过两种方式运行工作流：
  1. **自动触发**：每天北京时间约7:30自动执行（根据GitHub队列情况可能有波动）
  2. **手动触发**：点击 `Run workflow` 按钮，可选择 `push_mode`（推送模式：all/serverchan/dingtalk/email）后立即执行
- 再次进入 `Actions` 页面，点击 `Auto CVE Push Service` 工作流，检查最近一次运行是否有报错
- 若运行成功，系统将根据配置的推送方式（Server酱/钉钉/邮箱）发送通知（请确保已开启对应App的通知权限）
- 系统支持钉钉加签功能，如需启用请在GitHub Secrets中配置`DINGTALK_SECRET`

### 注意


- 请确保在仓库的`Settings`→`Actions`→`General`→`Workflow permissions`中开启**Read and write permissions**，以确保release报告的拉取和发布功能正常运行，避免出现403权限错误。

---

<p align="center">⚡ 如果本项目对你有帮助，请点一个 ⭐ Star 支持作者！</p> 

---

## 📅 更新日志

- 2025-09-13 🔄 增强翻译功能：新增Google翻译API作为容灾备份，有道翻译API失败时自动切换，提高系统稳定性
- 2025-09-13 🐛 修复环境变量处理问题：增强EMAIL_SMTP_PORT的类型转换逻辑，避免空字符串导致的ValueError错误
- 2025-09-13 🛠️ 优化GitHub Actions工作流：添加数据库下载失败的fallback机制，首次运行时自动创建空数据库文件，避免报错
- 2025-09-13 ✅ 新增漏洞分类标签功能：自动提取CWE信息并转换为中文标签，包括漏洞类型和严重性标签，在通知和报告中显示
- 2025-09-13 🔐 新增钉钉加签功能：支持配置DINGTALK_SECRET环境变量，增强钉钉机器人的安全性
- 2025-09-13 🔧 优化GitHub Actions工作流：支持手动触发时选择push_mode参数，灵活控制推送方式
- 2025-09-01 ⏰ 优化自动执行时间：调整为每天北京时间约7:30自动运行
- 2025-08-31 🎉 首次发布：支持高危漏洞自动推送，集成GitHub Actions

> 计划功能：
- 🔲 实现POC/EXP跟踪：针对已曝出漏洞实时跟踪全网POC/EXP情况，自动通知

---

## 💾 报告存储格式

项目会自动生成每日漏洞报告，并按照以下目录结构存储：
```
data/YYYY/W-WWDD/daily.md
```

- **YYYY**: 年份，例如：2025
- **WW**: 周数，例如：37
- **DD**: 日期，例如：13

示例路径：`data/2025/W37-0913/daily.md`

生成的报告包含当天所有高危漏洞的详细信息，按CVSS评分分组展示。

## 📦 GitHub Release 发布

当发现新的漏洞时，系统会自动将报告打包并发布为GitHub Release：

- **Tag格式**：`YYYY-MM-DD_DailyPush`（例如：`2025-09-13_DailyPush`）
- **打包内容**：`data/`目录下的所有文件，以`tar.gz`格式压缩
- **访问方式**：可在项目的Releases页面下载完整报告包

这一功能使得漏洞报告可以长期保存，方便用户随时查阅历史漏洞信息。

## 💡 致谢

- 感谢 [kiang70](https://github.com/kiang70/Github-Monitor/)、[Kira-Pgr](https://github.com/Kira-Pgr/Github-CVE-Listener)两位师傅提供思路。
- 感谢 [Server酱3](https://sc3.ft07.com/) 提供稳定的消息推送服务。
- 感谢 [NVD](https://nvd.nist.gov/) 提供权威的漏洞情报源。
- 翻译由 **有道开放平台** 、**Google translator** 提供。




