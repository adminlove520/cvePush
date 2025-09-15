# 项目目录结构说明

本项目采用清晰的目录结构组织代码和资源，方便维护和扩展。以下是项目的主要目录和文件说明：

## 主要目录

### docs/
存放项目文档，包括使用说明和测试指南。
- **README.md**: 项目主要说明文档，介绍项目功能、使用方法等
- **LOCAL_TEST_GUIDE.md**: 本地测试指南，提供在本地环境运行项目的详细步骤
- **LICENSE**: 项目许可证文件
- **Feature.md**: 项目功能特性说明
- **DIRECTORY_STRUCTURE.md**: 项目目录结构说明
- **REFACTOR_PLAN.md**: 项目重构计划文档

### config/
存放配置文件。
- **config.yaml**: 项目配置文件，包含数据源配置、缓存设置等

### logs/
存放日志文件，便于调试和问题追踪。

### data/
存放漏洞数据和生成的报告。
- 按年/周-日期格式组织的目录结构，存储每日漏洞报告
- **db/**: 数据库文件存储目录

### src/
项目核心代码目录，采用模块化设计。
- **__init__.py**: 包初始化文件
- **core/**: 核心功能模块
  - **cve_collector.py**: CVE数据采集模块
  - **cve_processor.py**: CVE数据处理模块
- **monitor/**: 监控功能模块
  - **poc_monitor.py**: POC监控模块
- **utils/**: 工具函数模块
  - **db_manager.py**: 数据库管理
  - **date_helper.py**: 日期处理
  - **file_helper.py**: 文件操作
  - **cache_helper.py**: 缓存管理
  - **translation_helper.py**: 翻译功能
  - **security_utils.py**: 安全相关工具
  - **notification_helper.py**: 通知辅助功能
- **config/**: 配置管理模块
  - **settings.py**: 设置管理
  - **logging_config.py**: 日志配置

### archive/
存放归档的旧代码文件，保留历史版本。

## 主要文件

### main.py
项目的主入口文件，负责初始化配置、调用各模块功能和处理命令行参数。

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
4. 运行`main.py`启动核心服务，支持多种命令行参数