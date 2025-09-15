# 项目目录结构说明

本项目采用清晰的目录结构组织代码和资源，方便维护和扩展。以下是项目的主要目录和文件说明：

## 主要目录

### docs/
存放项目文档，包括使用说明和测试指南。
- **README.md**: 项目主要说明文档，介绍项目功能、使用方法等
- **LOCAL_TEST_GUIDE.md**: 本地测试指南，提供在本地环境运行项目的详细步骤
- **LICENSE**: 项目许可证文件

### config/
存放配置文件。
- **config.yaml**: 项目配置文件，包含数据源配置、缓存设置等

### logs/
存放日志文件，便于调试和问题追踪。
- **cveflows.log**: 主服务程序的日志文件（按日期轮转）

### data/
存放漏洞数据和生成的报告。
- 按年/周-日期格式组织的目录结构，存储每日漏洞报告

### utils/
存放工具函数和公共模块，提供共享功能支持。
- **__init__.py**: 包初始化文件，定义公共接口
- **db_utils.py**: 数据库操作相关工具函数
- **helpers.py**: 辅助功能模块，包括日期处理、文件操作、缓存管理等

## 主要文件

### CVE_PushService.py
项目的核心服务程序，负责从NVD获取漏洞数据、筛选高危漏洞并通过多种渠道推送信息。

### poc_monitor.py
POC监控程序，用于搜索和监控与CVE漏洞相关的POC信息。

### requirements.txt
项目依赖列表，包含运行项目所需的Python包。

### .env.example
环境变量配置示例文件，提供配置模板。使用时请复制并重命名为`.env`。

### .gitignore
Git忽略文件配置，指定不提交到版本控制系统的文件和目录。

### .github/workflows/
存放GitHub Actions工作流配置文件，用于自动化运行项目。
- **AutoCVE.yml**: 自动CVE推送服务工作流
- **poc_monitor.yml**: POC监控工作流

## 如何使用

1. 阅读`docs/README.md`了解项目功能和基本使用方法
2. 参考`docs/LOCAL_TEST_GUIDE.md`配置本地开发环境
3. 根据需要修改`config/config.yaml`中的配置项
4. 运行`CVE_PushService.py`启动核心服务