import logging
import requests
import time
import json
import logging
from typing import Dict, List, Optional, Union
from datetime import datetime, timedelta, timezone

# 定义UTC时区
UTC = timezone.utc
import xml.etree.ElementTree as ET
import gzip
import io
import os
import re

from src.config import settings
from src.utils.db_manager import db_manager
from src.utils.cache_helper import cache_helper
from src.utils.date_helper import date_helper

logger = logging.getLogger(__name__)

class CVECollector:
    """CVE信息收集器"""
    
    def __init__(self):
        """初始化CVE收集器"""
        # 从配置获取API设置
        self.nvd_api_url = settings.get('API.nvd.base_url', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
        self.nvd_api_key = settings.get('API.nvd.api_key', '')
        self.nvd_rate_limit = settings.get('API.nvd.rate_limit', 5)  # 每秒请求数
        
        # 上次请求时间，用于限制速率
        self.last_request_time = time.time()
        
        # 重试设置
        self.max_retries = settings.get('POC_MONITOR.max_retries', 3)
        self.retry_interval = settings.get('POC_MONITOR.retry_interval', 5)
        
        # NVD数据feed URL
        self.nvd_recent_feed_url = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz'
        self.nvd_year_feed_url_template = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz'
    
    def _throttle_request(self) -> None:
        """根据速率限制控制请求频率"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        # 计算需要等待的时间
        min_interval = 1.0 / self.nvd_rate_limit
        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            logger.debug(f"请求速率限制，等待 {wait_time:.2f} 秒")
            time.sleep(wait_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, url: str, params: Dict = None, headers: Dict = None) -> Optional[Dict]:
        """发送HTTP请求，处理重试和错误
        
        Args:
            url: 请求URL
            params: 请求参数
            headers: 请求头
            
        Returns:
            Optional[Dict]: 响应数据（如果请求成功）
        """
        if headers is None:
            headers = {
                'User-Agent': settings.get('APP.user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            }
        
        # 如果有API密钥，添加到请求头
        if self.nvd_api_key and 'nvd.nist.gov' in url:
            headers['apiKey'] = self.nvd_api_key
        
        retries = 0
        while retries < self.max_retries:
            try:
                self._throttle_request()
                
                logger.debug(f"发送请求: {url}, 参数: {params}")
                response = requests.get(url, params=params, headers=headers, timeout=30)
                
                # 检查响应状态
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:
                    # 速率限制，等待更长时间
                    wait_time = min(self.retry_interval * (2 ** retries), 60)
                    logger.warning(f"请求被速率限制，等待 {wait_time} 秒后重试")
                    time.sleep(wait_time)
                    retries += 1
                elif response.status_code >= 500:
                    # 服务器错误，重试
                    logger.warning(f"服务器错误: {response.status_code}, 等待 {self.retry_interval} 秒后重试")
                    time.sleep(self.retry_interval)
                    retries += 1
                else:
                    # 其他错误，不重试
                    logger.error(f"请求失败: {response.status_code}, 响应: {response.text}")
                    return None
            except requests.RequestException as e:
                logger.error(f"请求异常: {str(e)}")
                retries += 1
                if retries < self.max_retries:
                    time.sleep(self.retry_interval)
            except ValueError as e:
                logger.error(f"解析响应JSON失败: {str(e)}")
                return None
        
        logger.error(f"达到最大重试次数 ({self.max_retries})，请求失败")
        return None
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """根据CVE ID获取漏洞信息
        
        Args:
            cve_id: CVE标识符，如 'CVE-2023-1234'
            
        Returns:
            Optional[Dict]: CVE信息
        """
        if not cve_id.startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        
        # 1. 从数据库检查
        db_data = db_manager.get_cve_info(cve_id)
        if db_data:
            # 转换为字典格式
            cve_data = {
                'id': db_data[0],
                'description': db_data[1],
                'severity': db_data[2],
                'published_date': db_data[3],
                'last_modified_date': db_data[4],
                'cvss_score': db_data[5],
                'references': json.loads(db_data[6]) if db_data[6] else [],
                'tags': json.loads(db_data[7]) if db_data[7] else [],
                'source': db_data[8],
                'is_new': db_data[9],
                'poc_info': json.loads(db_data[10]) if db_data[10] else {},
                'created_at': db_data[11]
            }
            
            logger.debug(f"从数据库获取CVE信息: {cve_id}")
            return cve_data
        
        # 2. 从NVD的压缩数据feed中查找
        try:
            # 获取最近的CVE数据
            recent_cves = self.fetch_nvd_data(use_recent=True)
            
            # 在最近的数据中查找特定CVE
            for cve_vuln in recent_cves:
                if isinstance(cve_vuln, dict):
                    # 检查数据结构
                    if 'cve' in cve_vuln and isinstance(cve_vuln['cve'], dict):
                        # 完整的数据结构
                        if cve_vuln['cve'].get('CVE_data_meta', {}).get('ID') == cve_id:
                            cve_data = self._parse_nvd_cve_item(cve_vuln)
                            self._save_cve_to_db(cve_data)
                            logger.info(f"从NVD数据feed获取CVE信息: {cve_id}")
                            return cve_data
                    elif cve_vuln.get('id') == cve_id:
                        # 简化的数据结构
                        self._save_cve_to_db(cve_vuln)
                        logger.info(f"从NVD数据feed获取CVE信息: {cve_id}")
                        return cve_vuln
            
            # 如果最近的数据中没有，尝试获取年度数据
            year = cve_id.split('-')[1]
            if year.isdigit():
                # 构造年度数据URL
                year_url = self.nvd_year_feed_url_template.format(year)
                
                try:
                    logger.info(f"Fetching year data from: {year_url}")
                    # 设置合适的请求头
                    headers = {
                        'User-Agent': settings.get('APP.user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    }
                    
                    response = requests.get(year_url, stream=True, timeout=60, headers=headers)
                    response.raise_for_status()

                    with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz_file:
                        year_data = json.loads(gz_file.read().decode('utf-8'))
                        year_cves = year_data.get('vulnerabilities', [])
                        
                        # 在年度数据中查找特定CVE
                        for cve_vuln in year_cves:
                            if isinstance(cve_vuln, dict) and 'cve' in cve_vuln:
                                if cve_vuln['cve'].get('CVE_data_meta', {}).get('ID') == cve_id:
                                    cve_data = self._parse_nvd_cve_item(cve_vuln)
                                    self._save_cve_to_db(cve_data)
                                    logger.info(f"从NVD年度数据feed获取CVE信息: {cve_id}")
                                    return cve_data
                except Exception as e:
                    logger.error(f"Failed to fetch NVD year data: {str(e)}")
        except Exception as e:
            logger.error(f"Error fetching CVE from NVD feed: {str(e)}")
        
        logger.warning(f"未找到CVE信息: {cve_id}")
        return None
    
    def _parse_nvd_cve_item(self, cve_item: Dict) -> Dict:
        """解析NVD的CVE项目数据（兼容1.0版本）
        
        Args:
            cve_item: NVD返回的CVE项目数据
            
        Returns:
            Dict: 解析后的CVE信息
        """
        # 基础信息
        cve_id = cve_item['cve']['CVE_data_meta']['ID']
        
        # 描述
        descriptions = cve_item['cve']['description']['description_data']
        description = descriptions[0]['value'] if descriptions else ''
        # 尝试获取中文描述
        for desc in descriptions:
            if desc.get('lang') == 'zh':
                description = desc['value']
                break
        
        # 严重性和CVSS评分
        severity = 'UNKNOWN'
        cvss_score = 0.0
        
        # 优先使用CVSS v3
        if 'impact' in cve_item and 'baseMetricV3' in cve_item['impact']:
            impact_v3 = cve_item['impact']['baseMetricV3']
            severity = impact_v3['cvssV3']['baseSeverity']
            cvss_score = impact_v3['cvssV3']['baseScore']
        # 其次使用CVSS v2
        elif 'impact' in cve_item and 'baseMetricV2' in cve_item['impact']:
            impact_v2 = cve_item['impact']['baseMetricV2']
            severity = impact_v2['severity']
            cvss_score = impact_v2['cvssV2']['baseScore']
        
        # 日期信息
        published_date = cve_item['publishedDate']
        last_modified_date = cve_item['lastModifiedDate']
        
        # 参考信息
        references = []
        if 'references' in cve_item['cve']:
            for ref in cve_item['cve']['references']['reference_data']:
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('refsource', ''),
                    'tags': ref.get('tags', [])
                })
        
        # 构造返回数据
        return {
            'id': cve_id,
            'description': description,
            'severity': severity,
            'published_date': published_date,
            'last_modified_date': last_modified_date,
            'cvss_score': cvss_score,
            'references': references,
            'tags': [],  # 将在后续处理中添加
            'source': 'NVD',
            'is_new': True,
            'poc_info': {},  # 将在POC查找器中填充
            'created_at': datetime.now().isoformat()
        }
        
    def _parse_nvd_cve_item_v2(self, cve_item: Dict) -> Dict:
        """解析NVD的CVE项目数据（针对2.0版本API）
        
        Args:
            cve_item: NVD 2.0 API返回的CVE项目数据
            
        Returns:
            Dict: 解析后的CVE信息
        """
        try:
            # 适配不同的数据结构
            # 从压缩feed中获取的数据结构
            if isinstance(cve_item, dict) and 'cve' in cve_item:
                # 基础信息
                cve_id = cve_item['cve'].get('id', 'UNKNOWN')
                logger.debug(f"解析CVE ID: {cve_id}")
                
                # 描述
                descriptions = cve_item['cve'].get('descriptions', [])
                description = descriptions[0].get('value', '') if descriptions else ''
                # 尝试获取中文描述
                for desc in descriptions:
                    if desc.get('lang') == 'zh':
                        description = desc.get('value', '')
                        break
                
                # 严重性和CVSS评分
                severity = 'UNKNOWN'
                cvss_score = 0.0
                
                # 优先使用CVSS v3
                metrics = cve_item['cve'].get('metrics', {})
                
                # 尝试从metrics中获取评分
                if metrics:
                    # 检查是否有V31评分
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        severity = metrics['cvssMetricV31'][0].get('baseSeverity', 'UNKNOWN')
                        cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0.0)
                    # 检查是否有V30评分
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        severity = metrics['cvssMetricV30'][0].get('baseSeverity', 'UNKNOWN')
                        cvss_score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0.0)
                    # 检查是否有V2评分
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'UNKNOWN')
                        cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0.0)
                
                # 补充：如果通过metrics未获取到评分，尝试从cve对象的其他可能字段获取
                if cvss_score == 0.0:
                    # 检查cve_item中是否有直接的评分字段
                    if 'cvss' in cve_item['cve']:
                        cvss_data = cve_item['cve']['cvss']
                        if isinstance(cvss_data, dict):
                            if 'baseScore' in cvss_data:
                                cvss_score = cvss_data['baseScore']
                            if 'baseSeverity' in cvss_data:
                                severity = cvss_data['baseSeverity']
                
                # 最后验证严重性和分数的一致性
                if cvss_score > 0 and severity == 'UNKNOWN':
                    # 根据CVSS分数推断严重性
                    if cvss_score >= 9.0:
                        severity = 'CRITICAL'
                    elif cvss_score >= 7.0:
                        severity = 'HIGH'
                    elif cvss_score >= 4.0:
                        severity = 'MEDIUM'
                    elif cvss_score > 0:
                        severity = 'LOW'
                
                # 如果通过metrics没有获取到评分，尝试从其他字段获取
                if cvss_score == 0.0 and 'cvssMetricV31' not in metrics and 'cvssMetricV30' not in metrics and 'cvssMetricV2' not in metrics:
                    logger.debug(f"尝试从其他字段获取评分: {cve_id}")
                    # 有些CVE可能直接在cve对象中有评分信息
                    if 'metrics' in cve_item['cve']:
                        # 尝试其他可能的评分字段
                        for metric_type, metric_list in cve_item['cve']['metrics'].items():
                            if metric_list and isinstance(metric_list, list):
                                # 检查是否有baseSeverity字段
                                if 'baseSeverity' in metric_list[0]:
                                    severity = metric_list[0]['baseSeverity']
                                # 检查是否有baseScore字段
                                if 'baseScore' in metric_list[0]:
                                    cvss_score = metric_list[0]['baseScore']
                                elif 'cvssData' in metric_list[0] and 'baseScore' in metric_list[0]['cvssData']:
                                    cvss_score = metric_list[0]['cvssData']['baseScore']
                                break
                
                # 日期信息 - 从正确的位置获取日期
                published_date = cve_item.get('published', '')
                last_modified_date = cve_item.get('lastModified', '')
                
                # 如果日期为空，尝试从其他位置获取
                if not published_date:
                    published_date = cve_item['cve'].get('published', '')
                if not last_modified_date:
                    last_modified_date = cve_item['cve'].get('lastModified', '')
                
                # 参考信息
                references = []
                ref_data = cve_item['cve'].get('references', [])
                for ref in ref_data:
                    references.append({
                        'url': ref.get('url', ''),
                        'source': ref.get('source', ''),
                        'tags': ref.get('tags', [])
                    })
            else:
                # 回退到旧的解析方式
                logger.warning("无效的CVE数据结构")
                cve_id = 'UNKNOWN'
                description = ''
                severity = 'UNKNOWN'
                cvss_score = 0.0
                published_date = ''
                last_modified_date = ''
                references = []
            
            logger.debug(f"CVE {cve_id} 解析完成: severity={severity}, score={cvss_score}")
            
            # 构造返回数据
            return {
                'id': cve_id,
                'description': description,
                'severity': severity,
                'published_date': published_date,
                'last_modified_date': last_modified_date,
                'cvss_score': cvss_score,
                'references': references,
                'tags': [],  # 将在后续处理中添加
                'source': 'NVD',
                'is_new': True,
                'poc_info': {},  # 将在POC查找器中填充
                'created_at': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"解析NVD 2.0 API数据时出错: {str(e)}")
            # 返回基本结构，避免程序崩溃
            return {
                'id': 'UNKNOWN',
                'description': '解析错误',
                'severity': 'UNKNOWN',
                'published_date': '',
                'last_modified_date': '',
                'cvss_score': 0.0,
                'references': [],
                'tags': [],
                'source': 'NVD',
                'is_new': True,
                'poc_info': {},
                'created_at': datetime.now().isoformat()
            }
    
    def get_recent_cves(self, days: int = 1, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict]:
        """获取最近的CVE漏洞列表
        
        Args:
            days: 过去几天内的漏洞，默认为1天
            start_date: 开始日期（格式：YYYY-MM-DD）
            end_date: 结束日期（格式：YYYY-MM-DD）
            
        Returns:
            List[Dict]: CVE信息列表
        """
        # 确定日期范围 - 统一使用UTC时间
        if not start_date:
            end = datetime.now(UTC) if not end_date else datetime.strptime(end_date, '%Y-%m-%d').replace(tzinfo=UTC)
            start = end - timedelta(days=days)
            start_date = start.strftime('%Y-%m-%d')
            if not end_date:
                end_date = end.strftime('%Y-%m-%d')
        
        logger.info(f"日期范围: {start_date} 到 {end_date}")
        
        # 检查缓存 - 添加当前小时到缓存键，确保每小时更新
        current_hour = datetime.now(UTC).strftime('%Y%m%d%H')
        cache_key = f'recent_cves_{start_date}_{end_date}_{current_hour}'
        cached_data = cache_helper.get_cached_data(cache_key)
        if cached_data:
            logger.debug(f"从缓存获取最近CVE列表: {start_date} 到 {end_date}")
            return cached_data
        
        # 使用基于文件下载的方法获取CVE数据
        cve_items = self.fetch_nvd_data(use_recent=True)
        
        all_cves = []
        valid_count = 0
        skipped_count = 0
        
        logger.info(f"获取到的原始CVE项数量: {len(cve_items) if cve_items else 0}")
        
        if cve_items:
            # 创建日期范围对象
            start_dt = datetime.strptime(start_date, '%Y-%m-%d').replace(tzinfo=UTC)
            end_dt = datetime.strptime(end_date, '%Y-%m-%d').replace(tzinfo=UTC, hour=23, minute=59, second=59)
            
            for item in cve_items:
                try:
                    # 使用针对2.0版本的解析方法，传递完整的item对象
                    cve_data = self._parse_nvd_cve_item_v2(item)
                    valid_count += 1
                    
                    # 检查ID是否有效
                    if cve_data.get('id') == 'UNKNOWN':
                        skipped_count += 1
                        continue
                    
                    # 检查是否在指定时间范围内（如果有日期）
                    published_date = cve_data.get('published_date', '')
                    if published_date:
                        try:
                            # 解析日期并添加时区
                            if 'Z' in published_date:
                                pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                            elif '+' in published_date or '-' in published_date.split('T')[1]:
                                pub_date = datetime.fromisoformat(published_date)
                            else:
                                # 尝试多种格式解析
                                try:
                                    pub_date = datetime.fromisoformat(published_date).replace(tzinfo=UTC)
                                except ValueError:
                                    # 使用strptime尝试常见格式
                                    formats = ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d']
                                    pub_date = None
                                    for fmt in formats:
                                        try:
                                            pub_date = datetime.strptime(published_date, fmt).replace(tzinfo=UTC)
                                            break
                                        except ValueError:
                                            continue
                                    
                                    # 如果仍然无法解析，假设日期有效
                                    if pub_date is None:
                                        pub_date = datetime.now(UTC)
                        except Exception as e:
                            logger.error(f"解析日期失败: {published_date}, 错误: {str(e)}")
                            pub_date = datetime.now(UTC)
                        
                        # 简化日期比较逻辑，只比较日期部分
                        try:
                            # 提取日期部分（年月日）进行比较
                            pub_date_only = pub_date.date()
                            start_date_only = start_dt.date()
                            end_date_only = end_dt.date()
                            
                            if start_date_only <= pub_date_only <= end_date_only:
                                all_cves.append(cve_data)
                                # 保存到数据库
                                self._save_cve_to_db(cve_data)
                                logger.debug(f"添加CVE: {cve_data.get('id')}, 严重性: {cve_data.get('severity')}")
                            else:
                                skipped_count += 1
                        except Exception as e:
                            logger.error(f"日期比较失败: {str(e)}")
                            # 如果比较失败，仍然添加到列表中
                            all_cves.append(cve_data)
                            self._save_cve_to_db(cve_data)
                    else:
                        # 如果没有日期信息，仍然添加到列表中
                        all_cves.append(cve_data)
                        self._save_cve_to_db(cve_data)
                        logger.debug(f"添加无日期CVE: {cve_data.get('id')}")
                except Exception as e:
                    logger.error(f"处理CVE项时出错: {str(e)}")
                    skipped_count += 1
                    continue
        
        # 缓存结果
        cache_helper.cache_data(cache_key, all_cves)
        
        logger.info(f"获取到 {len(all_cves)} 个最近的CVE漏洞")
        return all_cves
        
    def fetch_nvd_data(self, use_recent=True, year=None):
        """从NVD获取CVE数据
        
        Args:
            use_recent: 是否获取最近的CVE数据
            year: 可选，指定获取哪一年的数据
            
        Returns:
            List: CVE数据列表
        """
        if use_recent:
            url = self.nvd_recent_feed_url
        else:
            target_year = year if year else datetime.now().year
            url = self.nvd_year_feed_url_template.format(target_year)

        try:
            logger.info(f"Fetching data from: {url}")
            # 设置合适的请求头
            headers = {
                'User-Agent': settings.get('APP.user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            }
            
            response = requests.get(url, stream=True, timeout=30, headers=headers)
            response.raise_for_status()

            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz_file:
                data = json.loads(gz_file.read().decode('utf-8'))
                return data.get('vulnerabilities', [])
        except Exception as e:
            logger.error(f"Failed to fetch NVD data: {str(e)}")
            return []
    
    def fetch_full_year_data(self, year=None):
        """获取指定年份的全量CVE数据
        
        Args:
            year: 可选，指定获取哪一年的数据，默认为当前年份
            
        Returns:
            Dict: 包含年份和CVE数据列表的字典
        """
        target_year = year if year else datetime.now().year
        logger.info(f"开始获取{target_year}年的全量CVE数据")
        
        # 获取年度数据
        year_data = self.fetch_nvd_data(use_recent=False, year=target_year)
        
        if not year_data:
            logger.warning(f"未获取到{target_year}年的CVE数据")
            return {'year': target_year, 'data': []}
        
        logger.info(f"成功获取到{target_year}年的{len(year_data)}条CVE数据")
        
        return {
            'year': target_year,
            'data': year_data,
            'count': len(year_data),
            'fetch_time': datetime.now(UTC).isoformat()
        }
    
    def save_full_year_data_to_markdown(self, year_data, output_dir=None):
        """将全量年度数据保存为Markdown文件
        
        Args:
            year_data: 包含年份和CVE数据的字典
            output_dir: 输出目录，默认为data/db/
            
        Returns:
            str: 保存的文件路径，如果保存失败则返回None
        """
        from src.utils.file_helper import file_helper
        
        target_year = year_data.get('year')
        if not target_year:
            logger.error("无法确定要保存的年份")
            return None
        
        # 创建输出目录
        if not output_dir:
            output_dir = os.path.join(settings.BASE_DIR, 'data', 'db')
        
        # 确保目录存在
        file_helper.ensure_directory_exists(output_dir)
        
        # 构建文件路径
        file_path = os.path.join(output_dir, f'nvdData_{target_year}.md')
        
        try:
            # 创建Markdown内容
            md_content = []
            md_content.append(f"# NVD CVE 全量数据 {target_year}")
            md_content.append(f"> 数据获取时间: {year_data.get('fetch_time')}")
            md_content.append(f"> 共包含 {year_data.get('count', 0)} 条CVE记录")
            md_content.append("")
            md_content.append("| ID | 发布日期 | 严重性 | CVSS评分 | 描述 |")
            md_content.append("|----|---------|--------|---------|------|")
            
            # 处理每条CVE数据
            cve_list = year_data.get('data', [])
            processed_count = 0
            for item in cve_list:
                try:
                    cve_data = self._parse_nvd_cve_item_v2(item)
                    
                    # 提取需要的字段
                    cve_id = cve_data.get('id', 'UNKNOWN')
                    published_date = cve_data.get('published_date', 'N/A')
                    severity = cve_data.get('severity', 'UNKNOWN')
                    cvss_score = cve_data.get('cvss_score', 'N/A')
                    
                    # 清理描述，移除Markdown特殊字符
                    description = cve_data.get('description', 'N/A')
                    description = re.sub(r'[|\\]', '', description)  # 移除竖线和反斜杠
                    description = description[:200] + '...' if len(description) > 200 else description
                    
                    # 添加到表格行
                    md_content.append(f"| {cve_id} | {published_date} | {severity} | {cvss_score} | {description} |")
                    
                    # 将数据保存到数据库
                    self._save_cve_to_db(cve_data)
                    processed_count += 1
                    
                    # 每处理100个记录记录一次日志
                    if processed_count % 100 == 0:
                        logger.info(f"已处理 {processed_count}/{len(cve_list)} 条CVE数据")
                except Exception as e:
                    logger.warning(f"处理CVE数据时出错: {str(e)}")
                    continue
            
            # 写入文件
            success = file_helper.write_file(file_path, '\n'.join(md_content))
            
            if success:
                logger.info(f"全量CVE数据已保存到: {file_path}")
                logger.info(f"共处理并保存了 {processed_count} 条CVE数据到数据库")
                return file_path
            else:
                logger.error(f"保存全量CVE数据失败")
                return None
        except Exception as e:
            logger.error(f"保存全量CVE数据到Markdown时出错: {str(e)}")
            return None
    
    def _save_cve_to_db(self, cve_data: Dict) -> bool:
        """将CVE信息保存到数据库
        
        Args:
            cve_data: CVE信息
            
        Returns:
            bool: 是否保存成功
        """
        try:
            # 检查是否已存在，同时传递发布日期进行新漏洞判断
            is_new = db_manager.is_new_vuln(cve_data['id'], cve_data.get('published_date'))
            
            # 更新cve_data中的is_new字段
            cve_data['is_new'] = is_new
            
            if is_new:
                # 准备数据
                vuln_data = (
                    cve_data['id'],
                    cve_data['description'],
                    cve_data['severity'],
                    cve_data['published_date'],
                    cve_data['last_modified_date'],
                    cve_data['cvss_score'],
                    json.dumps(cve_data['references']),
                    json.dumps(cve_data['tags']),
                    cve_data['source'],
                    cve_data['is_new'],
                    json.dumps(cve_data['poc_info']),
                    cve_data['created_at']
                )
                
                # 保存到数据库
                db_manager.save_vuln(*vuln_data)
                logger.debug(f"已保存新的CVE信息到数据库: {cve_data['id']}")
                return True
            else:
                logger.debug(f"CVE信息已存在于数据库或不是新发布的: {cve_data['id']}")
                return True
        except Exception as e:
            logger.error(f"保存CVE信息到数据库失败: {str(e)}")
            return False
    
    def search_cves(self, query: str, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict]:
        """搜索CVE漏洞
        
        Args:
            query: 搜索关键词
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            List[Dict]: 匹配的CVE信息列表
        """
        # 检查缓存
        cache_key = f'search_cves_{query}_{start_date or ""}_{end_date or ""}'
        cached_data = cache_helper.get_cached_data(cache_key)
        if cached_data:
            logger.debug(f"从缓存获取搜索结果: {query}")
            return cached_data
        
        # 从NVD API搜索
        url = self.nvd_api_url
        params = {
            'keywordSearch': query,
            'resultsPerPage': 1000
        }
        
        # 添加日期范围
        if start_date and end_date:
            params['pubStartDate'] = f'{start_date}T00:00:00:000 UTC-00:00'
            params['pubEndDate'] = f'{end_date}T23:59:59:999 UTC-00:00'
        
        all_cves = []
        start_index = 0
        
        while True:
            params['startIndex'] = start_index
            data = self._make_request(url, params)
            
            if not data or 'result' not in data:
                logger.error("搜索CVE失败")
                break
            
            result = data['result']
            if 'CVE_Items' in result:
                cve_items = result['CVE_Items']
                for item in cve_items:
                    cve_data = self._parse_nvd_cve_item(item)
                    all_cves.append(cve_data)
                    # 保存到数据库
                    self._save_cve_to_db(cve_data)
                
                # 检查是否还有更多结果
                total_results = result.get('totalResults', 0)
                if start_index + len(cve_items) >= total_results:
                    break
                
                start_index += len(cve_items)
            else:
                break
        
        # 缓存结果
        cache_helper.cache_data(cache_key, all_cves)
        
        logger.info(f"搜索 '{query}' 找到 {len(all_cves)} 个CVE漏洞")
        return all_cves
    
    def refresh_cve_cache(self, cve_id: str) -> bool:
        """刷新指定CVE的缓存
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            bool: 是否刷新成功
        """
        cache_key = f'cve_{cve_id.lower()}'
        
        # 清除缓存
        cache_helper.clear_cache(cache_key)
        
        # 重新获取数据
        cve_data = self.get_cve_by_id(cve_id)
        return cve_data is not None

# 创建默认实例
cve_collector = CVECollector()