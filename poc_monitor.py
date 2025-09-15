#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import yaml
import logging
import requests
import sqlite3
import time
import datetime
from datetime import datetime, timedelta, UTC
import hashlib
from pathlib import Path

# 导入工具包
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import (
    db_manager,
    get_cve_info_from_db,
    DateHelper,
    FileHelper,
    CacheHelper,
    TranslationHelper,
    translate
)

# 基本配置
DB_PATH = 'vulns.db'  # 数据库文件路径
CONFIG_FILE = 'config.yaml'  # 配置文件路径
POC_DATA_DIR = 'pocData'  # 存在POC的报告存储目录
NO_POC_DATA_DIR = 'data'  # 不存在POC的报告存储目录

# 日志配置
logger = logging.getLogger("PocMonitor")
logger.setLevel(logging.INFO)

# 控制台输出
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# 日志格式
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# 从配置文件加载配置
def load_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logger.error(f"加载配置文件失败: {str(e)}")
        # 返回默认配置
        return {
            'sources': [
                {
                    'name': 'Poc-Monitor_v1.0.1_update',
                    'url': 'https://raw.githubusercontent.com/adminlove520/Poc-Monitor_v1.0.1/main/update.json',
                    'type': 'json',
                    'priority': 1,
                    'enabled': True
                },
                {
                    'name': 'Poc-Monitor_v1.0.1_daily',
                    'url': 'https://raw.githubusercontent.com/adminlove520/Poc-Monitor_v1.0.1/main/dateLog/{date}.json',
                    'type': 'json',
                    'priority': 2,
                    'enabled': True
                }
            ],
            'cache': {
                'enabled': True,
                'cache_dir': '.cache',
                'cache_timeout': 3600
            }
        }

# 从所有数据源搜索CVE的POC信息
def search_poc_for_cve(cve_id, config):
    results = []
    seen_repos = set()  # 用于去重
    
    # 按优先级排序数据源
    sources = sorted(
        [s for s in config.get('sources', []) if s.get('enabled', True)],
        key=lambda x: x.get('priority', 999)
    )
    
    for source in sources:
        source_name = source.get('name', 'Unknown')
        source_url = source.get('url', '')
        
        logger.info(f"搜索CVE {cve_id} 在数据源: {source_name}")
        
        # 获取数据源数据
        data = CacheHelper.fetch_json_with_cache(source_url, config)
        if not data:
            continue
        
        # 搜索匹配的CVE
        poc_items = search_cve_in_data(cve_id, data)
        
        # 添加到结果中（去重）
        for item in poc_items:
            repo_url = f"https://github.com/{item.get('full_name', '')}"
            if repo_url not in seen_repos:
                seen_repos.add(repo_url)
                results.append({
                    'source': source_name,
                    'full_name': item.get('full_name', ''),
                    'url': repo_url,
                    'description': item.get('description', 'No description'),
                    'topics': item.get('topics', [])
                })
    
    logger.info(f"找到 {len(results)} 个匹配的POC仓库")
    return results

# 在数据中搜索特定CVE
def search_cve_in_data(cve_id, data):
    results = []
    
    # 根据数据结构类型进行搜索
    if isinstance(data, dict):
        # 检查是否有'new'字段（如update.json的结构）
        if 'new' in data and isinstance(data['new'], list):
            for item in data['new']:
                if is_cve_match(cve_id, item):
                    results.append(item)
        # 检查是否为直接的仓库列表
        elif isinstance(data.get('items'), list):
            for item in data['items']:
                if is_cve_match(cve_id, item):
                    results.append(item)
        else:
            # 尝试直接搜索整个字典
            for key, value in data.items():
                if isinstance(value, list):
                    for item in value:
                        if is_cve_match(cve_id, item):
                            results.append(item)
    elif isinstance(data, list):
        # 直接遍历列表
        for item in data:
            if is_cve_match(cve_id, item):
                results.append(item)
    
    return results

# 检查项目是否匹配CVE ID
def is_cve_match(cve_id, item):
    if not isinstance(item, dict):
        return False
    
    # 检查项目名称、全名或描述中是否包含CVE ID
    name = item.get('name', '').lower()
    full_name = item.get('full_name', '').lower()
    description = item.get('description', '').lower()
    cve_id_lower = cve_id.lower()
    
    return cve_id_lower in name or cve_id_lower in full_name or cve_id_lower in description

# 生成单个CVE的markdown报告
def generate_cve_markdown(cve_info, poc_results, has_poc):
    if not cve_info:
        return None
    
    # 使用CVE_PushService的翻译逻辑进行翻译
    original_description = cve_info['description']
    try:
        translated_description = translate(original_description)
    except Exception as e:
        logger.error(f"翻译失败: {str(e)}")
        translated_description = original_description
    
    # 获取原始标签信息
    original_tags = cve_info.get('tags', '未分类')
    
    # 根据是否存在POC调整漏洞分类标签
    if has_poc:
        # 存在POC的情况，添加(存在poc/exp)标签
        tags_list = original_tags.split(',')
        updated_tags = []
        severity_found = False
        
        for tag in tags_list:
            if tag == '严重':
                updated_tags.append(f"{tag}(存在poc/exp)")
                severity_found = True
            elif tag == '高危':
                updated_tags.append(f"{tag}(存在poc/exp)")
                severity_found = True
            else:
                updated_tags.append(tag)
        
        # 如果没有严重/高危标签，添加通用的(存在poc/exp)标签
        if not severity_found:
            updated_tags.append('存在poc/exp')
        
        vulnerability_classification = ", ".join(list(set(updated_tags)))
    else:
        # 不存在POC的情况，沿用原始标签
        vulnerability_classification = original_tags
    
    # 生成报告内容
    markdown_content = f"""
# {cve_info['id']} - CVSS: {cve_info['cvss_score']}

## 基本信息

**发布时间**: {cve_info['published_date']}
**攻击向量**: {cve_info['vector_string']}
**漏洞分类**: {vulnerability_classification}

## 漏洞描述

### 英文原文
{original_description}

### 中文译文
{translated_description}

## 相关链接

{cve_info['refs']}"""
    
    # 添加在野利用部分
    if poc_results:
        markdown_content += "\n## 在野利用\n\n"
        for i, poc in enumerate(poc_results, 1):
            topics_str = ", ".join(poc['topics']) if poc['topics'] else "无"
            markdown_content += f"{i}. [{poc['full_name']}]({poc['url']})\n"
            markdown_content += f"   - 描述: {poc['description']}\n"
            markdown_content += f"   - 标签: {topics_str}\n\n"
    
    # 添加报告尾部
    markdown_content += """

---
*本报告由 POC Monitor 自动生成*"""
    
    return markdown_content

# 保存CVE报告
def save_cve_report(cve_id, content, has_poc):
    if not content:
        return None
    
    # 根据是否有POC选择不同的存储目录
    data_dir = POC_DATA_DIR if has_poc else NO_POC_DATA_DIR
    
    # 获取日期格式并创建目录
    year = datetime.now(UTC).strftime('%Y')
    week_format = DateHelper.get_simple_week_date_format()
    dir_path = os.path.join(data_dir, year, week_format)
    
    # 确保目录存在
    if not FileHelper.ensure_directory_exists(dir_path):
        return None
    
    # 保存为文件
    file_path = os.path.join(dir_path, f'{cve_id}.md')
    if FileHelper.write_file(file_path, content):
        return file_path
    return None

# 处理单个CVE
def process_single_cve(cve_id):
    # 加载配置
    config = load_config()
    
    # 从数据库获取CVE信息
    cve_info = db_manager.get_cve_info(cve_id)
    if not cve_info:
        logger.error(f"无法处理CVE {cve_id}，数据库中未找到该漏洞信息")
        return False
    
    # 搜索POC信息
    poc_results = search_poc_for_cve(cve_id, config)
    
    # 确定是否存在POC
    has_poc = len(poc_results) > 0
    
    # 生成并保存报告
    markdown_content = generate_cve_markdown(cve_info, poc_results, has_poc)
    if markdown_content:
        file_path = save_cve_report(cve_id, markdown_content, has_poc)
        return file_path is not None
    
    return False

# 处理当日所有新漏洞
# （通过检查new_vulns.flag文件来获取当日新发现的漏洞）
def process_today_vulns():
    flag_file = "new_vulns.flag"
    
    # 检查是否存在标志文件
    if not os.path.exists(flag_file):
        logger.info("没有找到new_vulns.flag文件，当日可能没有新漏洞")
        return False
    
    try:
        # 读取标志文件
        content = FileHelper.read_file(flag_file)
        if not content:
            logger.warning("new_vulns.flag文件为空")
            return False
        
        lines = content.split('\n')
        if len(lines) < 2:
            logger.warning("new_vulns.flag文件格式不正确")
            return False
        
        # 获取当日新漏洞的数量和ID列表
        new_vulns_count = int(lines[0].strip())
        new_vuln_ids = [line.strip() for line in lines[1:] if line.strip()]
        
        logger.info(f"开始处理当日的 {new_vulns_count} 个新漏洞")
        
        # 处理每个漏洞
        success_count = 0
        for cve_id in new_vuln_ids:
            if process_single_cve(cve_id):
                success_count += 1
        
        logger.info(f"处理完成，成功生成 {success_count} 个CVE的POC监控报告")
        return True
        
    except Exception as e:
        logger.error(f"处理当日漏洞时出错: {str(e)}")
        return False

def main():
    logger.info("POC监控工具启动...")
    
    # 如果提供了CVE ID参数，则处理单个CVE
    if len(sys.argv) > 1:
        cve_id = sys.argv[1]
        logger.info(f"处理指定CVE: {cve_id}")
        result = process_single_cve(cve_id)
        sys.exit(0 if result else 1)
    
    # 否则处理当日所有新漏洞
    logger.info("开始处理当日所有新漏洞")
    result = process_today_vulns()
    
    logger.info("POC监控工具执行完毕")
    sys.exit(0 if result else 1)

if __name__ == '__main__':
    main()