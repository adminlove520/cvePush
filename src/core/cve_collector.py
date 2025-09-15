import logging
import requests
import time
import json
import logging
from typing import Dict, List, Optional, Union
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

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
        
        # 从数据库检查
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
        
        # 从NVD API获取（使用2.0版本的参数格式）
        params = {'cveId': cve_id}
        data = self._make_request(self.nvd_api_url, params=params)
        
        if data and 'result' in data and 'CVE_Items' in data['result'] and data['result']['CVE_Items']:
            cve_item = data['result']['CVE_Items'][0]
            # NVD API 2.0版本的响应格式可能有所不同，这里做兼容性处理
            # 检查是完整的CVE项目还是已经提取过的数据
            if 'cve' in cve_item and isinstance(cve_item['cve'], dict):
                cve_data = self._parse_nvd_cve_item(cve_item)
            elif 'id' in cve_item:
                # 如果已经是提取好的数据格式，直接使用
                cve_data = cve_item
            else:
                # 尝试使用新的解析方法
                cve_data = self._parse_nvd_cve_item_v2(cve_item)
            
            # 保存到数据库
            self._save_cve_to_db(cve_data)
            
            logger.info(f"成功获取CVE信息: {cve_id}")
            return cve_data
        
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
            # 基础信息 - API 2.0版本的结构
            cve_id = cve_item.get('cve', {}).get('id', 'UNKNOWN')
            
            # 描述 - API 2.0版本的描述结构
            descriptions = cve_item.get('cve', {}).get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            # 尝试获取中文描述
            for desc in descriptions:
                if desc.get('lang') == 'zh':
                    description = desc.get('value', '')
                    break
            
            # 严重性和CVSS评分 - API 2.0版本的评分结构
            severity = 'UNKNOWN'
            cvss_score = 0.0
            
            # 优先使用CVSS v3
            metrics = cve_item.get('cve', {}).get('metrics', {})
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                severity = metrics['cvssMetricV31'][0].get('baseSeverity', 'UNKNOWN')
                cvss_score = cvss_data.get('baseScore', 0.0)
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                severity = metrics['cvssMetricV30'][0].get('baseSeverity', 'UNKNOWN')
                cvss_score = cvss_data.get('baseScore', 0.0)
            # 其次使用CVSS v2
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'UNKNOWN')
                cvss_score = cvss_data.get('baseScore', 0.0)
            
            # 日期信息 - API 2.0版本的日期字段
            published_date = cve_item.get('published', '')
            last_modified_date = cve_item.get('lastModified', '')
            
            # 参考信息 - API 2.0版本的参考结构
            references = []
            ref_data = cve_item.get('cve', {}).get('references', [])
            for ref in ref_data:
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('source', ''),
                    'tags': ref.get('tags', [])
                })
            
            # 构造返回数据（保持与原方法相同的结构）
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
                'id': cve_item.get('cve', {}).get('id', 'UNKNOWN'),
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
        # 确定日期范围
        if not start_date:
            end = datetime.now() if not end_date else datetime.strptime(end_date, '%Y-%m-%d')
            start = end - timedelta(days=days)
            start_date = start.strftime('%Y-%m-%d')
            if not end_date:
                end_date = end.strftime('%Y-%m-%d')
        
        # 检查缓存
        cache_key = f'recent_cves_{start_date}_{end_date}'
        cached_data = cache_helper.get_cached_data(cache_key)
        if cached_data:
            logger.debug(f"从缓存获取最近CVE列表: {start_date} 到 {end_date}")
            return cached_data
        
        # 从NVD API获取（使用2.0版本格式）
        url = self.nvd_api_url
        
        # API 2.0版本的日期格式：ISO 8601
        start_datetime = f"{start_date}T00:00:00.000"
        end_datetime = f"{end_date}T23:59:59.999"
        
        params = {
            'pubStartDate': start_datetime,
            'pubEndDate': end_datetime,
            'resultsPerPage': 1000  # 每页最大数量
        }
        
        all_cves = []
        start_index = 0
        
        while True:
            params['startIndex'] = start_index
            data = self._make_request(url, params)
            
            if not data:
                logger.error("获取最近CVE列表失败")
                break
            
            # API 2.0版本的响应结构不同
            cve_items = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)
            
            if cve_items:
                for item in cve_items:
                    try:
                        # 使用针对2.0版本的解析方法
                        cve_data = self._parse_nvd_cve_item_v2(item.get('cve', {}))
                        all_cves.append(cve_data)
                        # 保存到数据库
                        self._save_cve_to_db(cve_data)
                    except Exception as e:
                        logger.error(f"处理CVE项时出错: {str(e)}")
                        continue
                
                # 检查是否还有更多结果
                if start_index + len(cve_items) >= total_results:
                    break
                
                start_index += len(cve_items)
            else:
                break
        
        # 缓存结果
        cache_helper.cache_data(cache_key, all_cves)
        
        logger.info(f"获取到 {len(all_cves)} 个最近的CVE漏洞")
        return all_cves
    
    def _save_cve_to_db(self, cve_data: Dict) -> bool:
        """将CVE信息保存到数据库
        
        Args:
            cve_data: CVE信息
            
        Returns:
            bool: 是否保存成功
        """
        try:
            # 检查是否已存在
            if db_manager.is_new_vuln(cve_data['id']):
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
                logger.debug(f"已保存CVE信息到数据库: {cve_data['id']}")
                return True
            else:
                logger.debug(f"CVE信息已存在于数据库: {cve_data['id']}")
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