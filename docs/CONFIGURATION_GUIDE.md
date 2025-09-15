# 配置指南

本指南详细介绍如何配置 CVE_PushService 中的 GitHub Token 和各种通知参数。关于全量数据同步功能的详细说明，请参考 [FULL_YEAR_SYNC_GUIDE.md](FULL_YEAR_SYNC_GUIDE.md) 文件。

## 配置方式概览

CVE_PushService 支持两种配置方式：

1. **环境变量配置**：通过 `.env` 文件或系统环境变量设置
2. **配置文件配置**：通过 `config/config.yaml` 文件设置

系统会优先使用环境变量中的配置，其次使用配置文件中的配置。这种设计使得在不同环境（如本地开发、GitHub Actions）中都能方便地进行配置。

## 配置系统优化

为了提高配置系统的一致性和可维护性，我们对配置系统进行了以下优化：

1. **配置键标准化**：系统会自动将配置文件中的 `cache` 和 `logging` 键标准化为大写的 `CACHE` 和 `LOGGING`，确保与 `settings.py` 中的 DEFAULT_SETTINGS 结构一致。
2. **配置项统一**：优化了 `config.yaml` 文件的结构，使其与 `settings.py` 中的 DEFAULT_SETTINGS 保持一致，包括键的大小写和配置项名称。
3. **完整配置说明**：配置文件中现在包含了更完整的配置项，使得配置更加清晰和易于理解。

## GitHub Token 配置

GitHub Token 用于增加 API 调用配额，避免触发 GitHub API 的速率限制。有两种方式配置 GitHub Token：

### 方法 1：在 .env 文件中配置

1. 打开项目根目录下的 `.env` 文件
2. 添加以下配置（如果不存在）：

```
# GitHub Token（也可以在config/config.yaml中配置）
GITHUB_TOKEN=您的GitHub Token
```

### 方法 2：在 config/config.yaml 文件中配置

1. 打开 `config/config.yaml` 文件
2. 找到或添加以下配置：

```yaml
API:
  github:
    token: 您的GitHub Token
```

## 通知参数配置

CVE_PushService 支持多种通知方式，包括钉钉、邮件和企业微信。以下是各种通知方式的配置方法。

### 钉钉通知配置

#### 方式 1：在 .env 文件中配置

```
# 钉钉推送配置
# 钉钉机器人的Webhook地址
DINGTALK_WEBHOOK=您的钉钉Webhook地址
# 钉钉机器人的加签密钥（可选，如启用加签功能）
DINGTALK_SECRET=您的钉钉加签密钥
```

#### 方式 2：在 config/config.yaml 文件中配置

```yaml
NOTIFICATION:
  dingtalk:
    enabled: true
    webhook_url: 您的钉钉Webhook地址
    secret_key: 您的钉钉加签密钥
```

### 邮件通知配置

#### 方式 1：在 .env 文件中配置

```
# 邮箱推送配置
# SMTP服务器地址（例如：smtp.qq.com）
EMAIL_SMTP_SERVER=您的SMTP服务器地址
# SMTP服务器端口（默认：587）
EMAIL_SMTP_PORT=587
# 发件人邮箱地址
EMAIL_USERNAME=您的发件人邮箱
# 发件人邮箱密码/授权码
EMAIL_PASSWORD=您的邮箱密码或授权码
# 发件人地址（可选，如与EMAIL_USERNAME不同时设置）
EMAIL_SENDER=您的发件人地址
# 收件人邮箱地址
EMAIL_RECEIVER=收件人邮箱地址
# 是否启用邮件通知
EMAIL_ENABLED=true
```

#### 方式 2：在 config/config.yaml 文件中配置

```yaml
NOTIFICATION:
  email:
    enabled: true
    smtp_server: 您的SMTP服务器地址
    smtp_port: 587
    username: 您的发件人邮箱
    password: 您的邮箱密码或授权码
    sender: 您的发件人邮箱
    recipients:
      - 收件人邮箱地址1
      - 收件人邮箱地址2
```

### 企业微信通知配置

#### 方式 1：在 .env 文件中配置

```
# 企业微信推送配置
# 企业微信机器人的Webhook地址
WECHAT_WORK_WEBHOOK=您的企业微信Webhook地址
```

#### 方式 2：在 config/config.yaml 文件中配置

```yaml
NOTIFICATION:
  wechat_work:
    enabled: true
    webhook_url: 您的企业微信Webhook地址
```

## 在 GitHub Actions 中使用

在 GitHub Actions 工作流中，您可以通过以下方式设置配置：

1. 在 GitHub 仓库的 "Settings" > "Secrets and variables" > "Actions" 中添加您的密钥作为 Actions secrets
2. 在 workflow 文件中引用这些 secrets 作为环境变量

示例 workflow 配置：

```yaml
jobs:
  cve_monitor:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
        
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: pip install -r requirements.txt
        
      - name: Run CVE monitor
        run: python main.py daily
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          DINGTALK_WEBHOOK: ${{ secrets.DINGTALK_WEBHOOK }}
          DINGTALK_SECRET: ${{ secrets.DINGTALK_SECRET }}
```

## 配置验证

您可以使用项目中的 `test_config.py` 脚本验证您的配置是否正确加载：

```bash
python test_config.py
```

该脚本会检查并显示：
- GitHub Token 的配置状态
- 各种通知渠道的配置状态
- 通知管理器的初始化状态

## 注意事项

1. 请确保您的 GitHub Token 有足够的权限（至少需要 `public_repo` 权限）
2. 不要将敏感的配置信息（如密码、密钥）提交到代码仓库中
3. 在生产环境中，建议使用环境变量或 GitHub Secrets 来配置敏感信息
4. 如果同时在 .env 文件和 config.yaml 文件中配置了相同的参数，系统会优先使用 .env 文件中的配置

如果您在配置过程中遇到任何问题，请查看项目日志文件（位于 `logs` 目录下）获取更多信息。