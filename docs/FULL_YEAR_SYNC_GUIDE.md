# 全量数据同步功能指南

本指南详细介绍 CVE_PushService 的全量数据同步功能，包括如何配置、使用和管理全量CVE数据。

## 功能概述

全量数据同步功能允许您获取并存储指定年份的完整CVE漏洞数据，生成结构化的Markdown格式报告，便于查阅和分析历史漏洞信息。

## 使用方式

### 1. 通过 GitHub Actions 自动化运行

项目提供了专门的 GitHub Actions 工作流 (`full_year_sync.yml`) 用于自动同步全量数据：

#### 配置与启用

1. 在 GitHub 仓库的 "Settings" > "Actions" 页面中，找到并启用 `Full Year CVE Data Sync` 工作流
2. 工作流支持两种触发方式：
   - **定时触发**：默认每月1日自动执行
   - **手动触发**：可通过 GitHub Actions 界面手动触发

#### 工作流参数

手动触发工作流时，您可以配置以下参数：

- **year**：指定要同步的年份（默认为当前年份）
- **force_update**：是否强制更新已存在的数据（可选，默认为false）

### 2. 本地运行

您也可以在本地环境中手动执行全量数据同步：

#### 环境准备

确保已完成以下准备工作：

1. 安装 Python 3.6 或更高版本
2. 安装依赖包：
   ```bash
   pip install -r requirements.txt
   ```
3. 配置 `.env` 文件，设置必要的环境变量

#### 执行命令

使用以下命令执行全量数据同步：

```bash
# 获取当前年份的全量CVE数据
python main.py full-year

# 获取指定年份的全量CVE数据
python main.py full-year --year 2024

# 强制更新指定年份的数据
python main.py full-year --year 2024 --force
```

## 数据存储结构

全量同步的数据会按照以下目录结构进行存储：

```
fullYearData/
├── YYYY/
│   ├── full_year_data.md       # 完整的年份漏洞数据报告
│   └── cve_details/            # 单个漏洞的详细信息
│       ├── CVE-YYYY-1234.md
│       ├── CVE-YYYY-5678.md
│       └── ...
```

- **full_year_data.md**：包含指定年份所有CVE漏洞的汇总报告，按CVSS评分分组展示
- **cve_details/**：目录下包含每个CVE漏洞的详细信息Markdown文件

## 报告内容说明

### 全量年份报告 (full_year_data.md)

该报告包含指定年份所有CVE漏洞的汇总信息，主要内容包括：

- 年份和数据统计信息
- 按CVSS评分分组的漏洞列表
- 每个漏洞的基本信息（ID、标题、CVSS评分、发布日期等）
- 漏洞描述摘要
- 相关参考链接

### 单个漏洞详情 (CVE-YYYY-XXXX.md)

每个CVE漏洞的详细信息文档包含：

- 漏洞基本信息（ID、标题、CVSS评分、严重性等）
- 完整的漏洞描述（包含中文翻译）
- 受影响的产品和版本
- 漏洞修复建议
- 参考链接（包括NVD官方链接、厂商公告等）
- CWE（通用漏洞枚举）信息

## 工作流执行流程

GitHub Actions 工作流的执行流程如下：

1. **代码检出**：从仓库克隆最新代码
2. **环境配置**：设置Python环境并安装依赖
3. **目录准备**：创建必要的数据存储目录
4. **年份确定**：根据参数或当前年份确定要同步的年份
5. **数据同步**：执行全量数据同步命令
6. **制品上传**：将生成的报告作为GitHub Actions制品上传
7. **结果通知**：在失败时记录日志信息

## 常见问题与解决方案

### 同步过程耗时较长

- 全量数据同步可能需要较长时间，特别是同步近期年份的数据
- GitHub Actions 工作流设置了60分钟超时时间，一般情况下足够完成同步

### 数据文件较大

- 完整年份的漏洞数据可能会生成较大的文件
- 建议使用支持大文件查看的Markdown阅读器打开报告

### 同步失败

- 检查GitHub Actions日志以获取详细错误信息
- 确认网络连接正常，NVD网站可访问
- 如遇限流问题，考虑配置GitHub Token以增加API调用配额

## 注意事项

1. 首次同步某一年份的数据时，可能需要较长时间，请耐心等待
2. 重复同步同一年份的数据（不使用强制更新）将跳过已存在的CVE
3. 使用强制更新参数会重新下载并覆盖所有数据
4. 生成的报告文件可能较大，特别是近期年份的数据

## 配置示例

以下是配置全量数据同步工作流的示例：

### GitHub Actions 工作流配置

```yaml
# 在 full_year_sync.yml 中
name: Full Year CVE Data Sync

on:
  schedule:
    # 每月1日执行
    - cron: '0 0 1 * *'
  workflow_dispatch:
    inputs:
      year:
        description: 'Year to sync (default: current year)'
        required: false
        type: string
      force_update:
        description: 'Force update existing data'
        required: false
        type: boolean
        default: false

# 工作流其余部分...
```

通过本指南，您可以充分利用全量数据同步功能，获取完整的历史漏洞数据，为安全分析和研究提供有力支持。