# 项目重构计划（已完成）

本文档记录了CVE_PushService项目的重构过程和成果。重构旨在优化项目代码结构，提高可维护性和可扩展性，并实现关键功能增强。

## 一、重构前代码结构分析

重构前项目主要包含以下文件：
- `CVE_PushService.py` - 主程序，包含数据获取、解析、通知和报告生成等核心功能
- `poc_monitor.py` - POC监控工具
- `utils/db_utils.py` - 数据库操作
- `utils/helpers.py` - 辅助功能（日期、文件、缓存、翻译）

## 二、重构目标

1. **代码结构优化**：将功能拆分为独立模块，提高模块化程度
2. **功能增强**：实现请求签名验证，提高API安全性
3. **性能优化**：改进翻译API调用，增加缓存机制
4. **可扩展性提升**：设计更灵活的接口和插件机制

## 三、重构后的目录结构

```
CVE_PushService/
├── src/
│   ├── __init__.py
│   ├── main.py                 # 程序入口
│   ├── core/
│   │   ├── __init__.py
│   │   ├── cve_collector.py    # CVE数据采集模块
│   │   ├── cve_processor.py    # CVE数据处理模块
│   ├── monitor/
│   │   ├── __init__.py
│   │   └── poc_monitor.py      # POC监控模块
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── db_manager.py       # 数据库管理
│   │   ├── date_helper.py      # 日期处理
│   │   ├── file_helper.py      # 文件操作
│   │   ├── cache_helper.py     # 缓存管理
│   │   ├── translation_helper.py # 翻译功能
│   │   ├── security_utils.py   # 安全相关工具
│   │   └── notification_helper.py # 通知辅助功能
│   └── config/
│       ├── __init__.py
│       ├── settings.py         # 设置管理
│       └── logging_config.py   # 日志配置
├── config/
│   └── config.yaml
├── data/
│   └── db/
├── docs/
│   ├── README.md
│   ├── LOCAL_TEST_GUIDE.md
│   ├── LICENSE
│   ├── Feature.md
│   ├── DIRECTORY_STRUCTURE.md
│   └── REFACTOR_PLAN.md
├── main.py
├── requirements.txt
└── archive/
    ├── CVE_PushService.py
    ├── poc_monitor.py
    ├── utils/
    ├── README.md.bak
    └── requirements.txt.bak
```

## 四、模块详细设计

### 1. 核心模块 (core/)

- **cve_collector.py**
  - 负责从NVD等源获取CVE数据
  - 实现请求重试和错误处理机制
  - 添加请求签名验证功能

- **cve_processor.py**
  - 解析CVE数据
  - 提取关键信息（CVSS评分、描述、参考链接等）
  - 生成漏洞标签

### 2. 监控模块 (monitor/)

- **poc_monitor.py**
  - POC监控的主逻辑
  - 处理单个CVE或当日所有新漏洞

### 3. 工具模块 (utils/)

- **db_manager.py**
  - 数据库连接和操作
  - 支持SQLite

- **date_helper.py**
  - 日期格式化和处理

- **file_helper.py**
  - 文件读写和目录管理

- **cache_helper.py**
  - 缓存管理（API响应缓存等）

- **translation_helper.py**
  - 翻译功能，支持多API容灾

- **security_utils.py**
  - 请求签名验证
  - 数据完整性检查

- **notification_helper.py**
  - 统一的通知发送接口
  - 支持Server酱、钉钉、邮件等多种通知方式
  - 实现钉钉加签验证

### 4. 配置模块 (config/)

- **settings.py**
  - 环境变量和配置文件管理
  - 提供默认配置

- **logging_config.py**
  - 日志配置

## 五、关键功能实现

### 1. 请求签名验证

实现基于HMAC-SHA256的请求签名验证机制，确保API请求的完整性和真实性。

### 2. 模块化的通知系统

设计统一的通知接口，支持多种通知方式，并易于扩展新的通知渠道。

### 3. 增强的缓存机制

改进缓存策略，减少重复的API调用，提高性能。

### 4. 优化的翻译功能

改进翻译API调用，增加重试机制和结果缓存。

## 六、重构步骤完成情况

1. ✅ 创建新的目录结构
2. ✅ 逐步迁移代码到新模块
3. ✅ 实现请求签名验证功能
4. ✅ 优化各模块间的接口
5. ✅ 更新GitHub Actions工作流
6. ✅ 归档旧代码文件
7. ✅ 验证功能完整性

## 七、重构成果

- 代码结构更加清晰，模块化程度更高
- 功能划分明确，便于维护和扩展
- 依赖项管理更加合理
- 文档更加完善
- GitHub Actions工作流与新代码结构完全匹配
- 所有核心功能保持不变