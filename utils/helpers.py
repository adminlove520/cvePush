#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import time
import requests
import json
import hashlib
from datetime import datetime, timedelta, UTC
from pathlib import Path

logger = logging.getLogger("Helpers")

class DateHelper:
    """日期处理辅助类"""
    
    @staticmethod
    def get_current_year():
        """获取当前年份"""
        return datetime.now().year
    
    @staticmethod
    def get_week_date_format(date=None):
        """获取周日期格式，返回格式: W(周)-mmdd"""
        if date is None:
            date = datetime.now(UTC).date()
        
        # 获取年份
        year = date.strftime('%Y')
        
        # 获取周数（W格式）
        week_number = date.strftime('%W')
        
        # 获取月日格式（MMDD）
        mmdd = date.strftime('%m%d')
        
        return f"{year}/W{week_number}-{mmdd}"
    
    @staticmethod
    def get_simple_week_date_format():
        """获取简化的周日期格式，返回格式: W(周)-mmdd"""
        now = datetime.now(UTC)
        week_number = now.strftime('%W')
        date_str = now.strftime('%m%d')
        return f"W{week_number}-{date_str}"
    
    @staticmethod
    def is_recent(published_date_str, hours=24):
        """检查日期是否在最近指定小时内发布"""
        try:
            # 将发布日期转换为UTC时区感知的datetime对象
            published_dt = datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC)
            time_diff = datetime.now(UTC) - published_dt
            return time_diff.total_seconds() <= hours * 3600
        except Exception as e:
            logger.error(f"解析日期 {published_date_str} 失败: {str(e)}")
            return False

class FileHelper:
    """文件操作辅助类"""
    
    @staticmethod
    def ensure_directory_exists(dir_path):
        """确保目录存在，如果不存在则创建"""
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path, exist_ok=True)
                logger.info(f"创建或确认目录存在: {dir_path}")
                return True
            except Exception as e:
                logger.error(f"创建目录失败: {str(e)}")
                return False
        return True
    
    @staticmethod
    def read_file(file_path, encoding='utf-8'):
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except Exception as e:
            logger.error(f"读取文件 {file_path} 失败: {str(e)}")
            return None
    
    @staticmethod
    def write_file(file_path, content, encoding='utf-8'):
        """写入文件内容"""
        try:
            # 确保目录存在
            directory = os.path.dirname(file_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            logger.info(f"文件已保存到: {file_path}")
            return True
        except Exception as e:
            logger.error(f"保存文件 {file_path} 失败: {str(e)}")
            return False

class CacheHelper:
    """缓存管理辅助类"""
    
    @staticmethod
    def get_cache_filename(url):
        """生成缓存文件名，使用URL的MD5哈希值"""
        md5_hash = hashlib.md5(url.encode()).hexdigest()
        return f"{md5_hash}.json"
    
    @staticmethod
    def is_cache_valid(cache_file, timeout):
        """检查缓存是否有效"""
        if not os.path.exists(cache_file):
            return False
        
        # 检查缓存文件的修改时间
        cache_time = os.path.getmtime(cache_file)
        current_time = time.time()
        
        return (current_time - cache_time) < timeout
    
    @staticmethod
    def fetch_json_with_cache(url, config):
        """从URL获取JSON数据，带缓存功能"""
        cache_config = config.get('cache', {})
        use_cache = cache_config.get('enabled', True)
        cache_dir = cache_config.get('cache_dir', '.cache')
        cache_timeout = cache_config.get('cache_timeout', 3600)
        
        # 替换URL中的日期占位符
        today = datetime.now(UTC).strftime('%Y-%m-%d')
        url = url.replace('{date}', today)
        
        # 如果启用缓存，检查缓存
        if use_cache:
            FileHelper.ensure_directory_exists(cache_dir)
            cache_file = os.path.join(cache_dir, CacheHelper.get_cache_filename(url))
            if CacheHelper.is_cache_valid(cache_file, cache_timeout):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        logger.info(f"使用缓存数据: {url}")
                        return json.load(f)
                except Exception as e:
                    logger.warning(f"读取缓存文件失败: {str(e)}")
        
        # 从URL获取数据
        try:
            logger.info(f"从URL获取数据: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # 保存到缓存
            if use_cache:
                FileHelper.ensure_directory_exists(cache_dir)
                cache_file = os.path.join(cache_dir, CacheHelper.get_cache_filename(url))
                try:
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f)
                except Exception as e:
                    logger.warning(f"保存缓存文件失败: {str(e)}")
                     
            return data
        except Exception as e:
            logger.error(f"获取URL数据失败: {str(e)}")
            return None

class TranslationHelper:
    """翻译辅助类"""
    
    @staticmethod
    def translate(text):
        """翻译文本，支持有道和Google翻译API容灾"""
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

# 导出主要类和函数
export = {
    'DateHelper': DateHelper,
    'FileHelper': FileHelper,
    'CacheHelper': CacheHelper,
    'TranslationHelper': TranslationHelper,
    'translate': TranslationHelper.translate,
    'get_current_year': DateHelper.get_current_year,
    'get_week_date_format': DateHelper.get_week_date_format
}