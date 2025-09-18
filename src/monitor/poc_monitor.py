import logging
import os
import json
import time
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional

# 配置requests重试机制
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socket

from src.utils.translation_helper import translation_helper
from src.utils.db_manager import db_manager
from src.utils.file_helper import file_helper
from src.utils.cache_helper import cache_helper
from src.core.cve_processor import CVEProcessor
from src.config import settings

logger = logging.getLogger(__name__)

class PocMonitor:
    """POC监控工具"""
    
    def __init__(self):
        """初始化POC监控工具"""
        # 基本配置
        self.new_vulns_flag = 'data/new_vulns.flag'
        self.check_interval = 3600  # 默认1小时
        
        # 从配置中加载POC数据源
        self.sources = settings.get('POC_MONITOR.sources', [])
        
        # 检查并处理数据源配置格式
        self._validate_and_process_sources()
        
        # 初始化处理器
        self.cve_processor = CVEProcessor()
        
    def _validate_and_process_sources(self):
        """验证并处理数据源配置，确保格式正确"""
        # 创建一个全新的有效数据源列表
        validated_sources = []
        current_year = datetime.now().year
        
        try:
            # 检查现有数据源是否有效
            if not self.sources or not isinstance(self.sources, list):
                # 如果没有有效数据源或不是列表，使用默认配置
                validated_sources = [
                    {
                        'name': 'Poc-Monitor_v1.0.1_update',
                        'url': 'https://raw.githubusercontent.com/adminlove520/Poc-Monitor_v1.0.1/main/update.json',
                        'priority': 1,
                        'enabled': True,
                        'type': 'json'
                    },
                    {
                        'name': 'Poc-Monitor_v1.0.1_daily',
                        'url': 'https://raw.githubusercontent.com/adminlove520/Poc-Monitor_v1.0.1/main/dateLog/{date}.json',
                        'priority': 2,
                        'enabled': True,
                        'type': 'json'
                    },
                    {
                        'name': 'PocOrExp_Today',
                        'url': 'https://github.com/ycdxsb/PocOrExp_in_Github/blob/main/Today.md',
                        'priority': 3,
                        'enabled': True,
                        'is_markdown': True,
                        'type': 'markdown'
                    },
                    {
                        'name': f'PocOrExp_{current_year}',
                        'url': f'https://github.com/ycdxsb/PocOrExp_in_Github/blob/main/{current_year}/README.md',
                        'priority': 4,
                        'enabled': True,
                        'is_markdown': True,
                        'type': 'markdown'
                    }
                ]
            else:
                # 处理现有数据源列表
                for i, item in enumerate(self.sources):
                    # 确保每个item都是字典格式
                    if not isinstance(item, dict):
                        # 对于非字典项，转换为字典格式
                        if isinstance(item, str):
                            # 假设字符串是URL
                            validated_source = {
                                'name': f'Source_{i}',
                                'url': item,
                                'priority': 999,
                                'enabled': True,
                                'type': 'json'
                            }
                        else:
                            # 对于其他类型，创建一个空数据源
                            validated_source = {
                                'name': f'Source_{i}',
                                'url': '',
                                'priority': 999,
                                'enabled': True,
                                'type': 'json'
                            }
                    else:
                        # 对于字典项，验证和补充必要字段
                        validated_source = item.copy()
                        
                        # 补充必要字段
                        if 'name' not in validated_source:
                            validated_source['name'] = f'Source_{i}'
                        if 'url' not in validated_source:
                            validated_source['url'] = ''
                        if 'priority' not in validated_source:
                            validated_source['priority'] = 999
                        if 'enabled' not in validated_source:
                            validated_source['enabled'] = True
                        if 'type' not in validated_source:
                            validated_source['type'] = 'json'
                        
                        # 根据类型设置is_markdown
                        if validated_source['type'] == 'markdown' and 'is_markdown' not in validated_source:
                            validated_source['is_markdown'] = True
                    
                    validated_sources.append(validated_source)
        except Exception as e:
            logger.error(f"处理数据源配置时出错: {str(e)}")
            # 发生错误时，使用默认配置
            validated_sources = [
                {
                        'name': 'Poc-Monitor_v1.0.1_update',
                        'url': 'https://raw.githubusercontent.com/adminlove520/Poc-Monitor_v1.0.1/main/update.json',
                        'priority': 1,
                        'enabled': True,
                        'type': 'json'
                    },
                    {
                        'name': 'Poc-Monitor_v1.0.1_daily',
                        'url': 'https://raw.githubusercontent.com/adminlove520/Poc-Monitor_v1.0.1/main/dateLog/{date}.json',
                        'priority': 2,
                        'enabled': True,
                        'type': 'json'
                    },
                    {
                        'name': 'PocOrExp_Today',
                        'url': 'https://github.com/ycdxsb/PocOrExp_in_Github/blob/main/Today.md',
                        'priority': 3,
                        'enabled': True,
                        'is_markdown': True,
                        'type': 'markdown'
                    },
                    {
                        'name': f'PocOrExp_{current_year}',
                        'url': f'https://github.com/ycdxsb/PocOrExp_in_Github/blob/main/{current_year}/README.md',
                        'priority': 4,
                        'enabled': True,
                        'is_markdown': True,
                        'type': 'markdown'
                    }
            ]
        
        # 使用验证后的数据源
        self.sources = validated_sources
    
    def search_poc_for_cve(self, cve_id: str) -> Dict:
        """搜索特定CVE的POC信息
        
        Args:
            cve_id: CVE编号
        
        Returns:
            包含POC信息的字典
        """
        # 检查缓存
        cache_key = f"poc_{cve_id}"
        cached_result = cache_helper.get_cached_data(cache_key)
        if cached_result:
            return cached_result
        
        # 检查数据库，添加错误处理
        try:
            cve_info = db_manager.get_cve_info(cve_id)
            if cve_info and len(cve_info) > 10:  # 确保数据有效且包含poc_info列
                poc_info_str = cve_info[10]  # poc_info列在vulns表中是第11列（索引从0开始）
                if poc_info_str:
                    try:
                        poc_info = json.loads(poc_info_str)
                        if poc_info and isinstance(poc_info, dict):
                            # 缓存结果
                            cache_helper.cache_data(cache_key, poc_info)
                            return poc_info
                    except json.JSONDecodeError:
                        logger.warning(f"解析CVE {cve_id} 的POC信息失败")
        except Exception as e:
            logger.warning(f"从数据库获取CVE信息时出错: {str(e)}")
        
        # 从配置的数据源中搜索POC信息
        logger.info(f"开始搜索CVE {cve_id} 的POC信息")
        
        # 按优先级排序启用的数据源
        enabled_sources = [s for s in self.sources if s.get('enabled', True)]
        sorted_sources = sorted(enabled_sources, key=lambda x: x.get('priority', 999))
        
        poc_items = []
        seen_urls = set()  # 用于去重
        
        for source in sorted_sources:
            source_name = source.get('name', 'Unknown')
            source_url = source.get('url', '')
            is_markdown = source.get('is_markdown', False)
            
            # 替换URL中的日期占位符
            today = datetime.now().strftime('%Y-%m-%d')
            url = source_url.replace('{date}', today)
            
            logger.info(f"从数据源 {source_name} 搜索: {url}")
            
            # 尝试从数据源获取数据，添加重试机制
            try:
                # 根据数据源类型设置不同的超时策略
                # 区分连接超时和读取超时，给GitHub链接更短的连接超时
                connect_timeout = 2 if 'github.com' in url else 3
                read_timeout = 3 if 'github.com' in url else 5
                timeout = (connect_timeout, read_timeout)
                
                # 创建session并配置重试
                session = requests.Session()
                
                # 为GitHub链接设置更激进的重试策略
                if 'github.com' in url:
                    retry = Retry(
                        total=2, 
                        backoff_factor=0.2, 
                        status_forcelist=[500, 502, 503, 504], 
                        connect=2, 
                        read=2, 
                        respect_retry_after_header=True  # 尊重服务器返回的Retry-After头
                    )
                else:
                    retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
                
                adapter = HTTPAdapter(max_retries=retry)
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                
                # 添加请求头，模拟浏览器请求
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                # 优化网络连接参数
                session.verify = True  # 验证SSL证书
                
                # 优化socket参数以减少超时问题
                session.trust_env = True  # 尊重环境变量中的代理设置
                
                # 发送请求，设置适当的超时时间和请求头
                logger.debug(f"发送请求到 {url}，超时配置: {timeout}")
                
                # 记录开始时间
                request_start_time = time.time()
                
                try:
                    # 先尝试解析主机名，检查DNS解析是否正常
                    if 'github.com' in url:
                        try:
                            hostname = 'github.com'
                            # 设置DNS解析超时为2秒
                            socket.setdefaulttimeout(2)
                            ip_address = socket.gethostbyname(hostname)
                            logger.debug(f"成功解析 {hostname} 的IP地址: {ip_address}")
                        except socket.gaierror as dns_error:
                            logger.warning(f"DNS解析失败: {str(dns_error)}，继续尝试连接...")
                        finally:
                            # 恢复默认超时设置
                            socket.setdefaulttimeout(None)
                    
                    # 发送请求
                    response = session.get(url, timeout=timeout, headers=headers, stream=True)
                    
                    # 特别处理429 Too Many Requests错误
                    if response.status_code == 429:
                        # 尝试获取Retry-After头
                        retry_after = response.headers.get('Retry-After')
                        if retry_after:
                            try:
                                wait_time = int(retry_after)
                                logger.warning(f"GitHub速率限制已触发，根据服务器建议等待 {wait_time} 秒")
                                time.sleep(wait_time)
                                # 等待后重试一次
                                response = session.get(url, timeout=timeout, headers=headers, stream=True)
                            except ValueError:
                                logger.warning(f"无法解析Retry-After头值: {retry_after}")
                    
                    response.raise_for_status()
                    
                    # 记录请求耗时
                    request_time = time.time() - request_start_time
                    logger.debug(f"请求完成，耗时: {request_time:.2f}秒")
                    
                    # 限制响应内容大小，防止处理过大的文件
                    content_length = response.headers.get('content-length')
                    if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB限制
                        logger.warning(f"响应内容过大 ({content_length} 字节)，跳过处理")
                        continue
                    
                    # 流式读取响应内容
                    response_text = response.text
                    
                except requests.exceptions.ProxyError as proxy_error:
                    # 特别处理代理错误
                    logger.error(f"代理连接失败: {str(proxy_error)}")
                    logger.info("尝试使用直接连接方式...")
                    
                    # 禁用代理重新尝试
                    try:
                        # 临时禁用代理
                        original_proxies = session.proxies
                        session.proxies = {}
                        
                        # 增加超时时间后重试
                        response = session.get(url, timeout=(5, 10), headers=headers, stream=True)
                        response.raise_for_status()
                        response_text = response.text
                        
                        logger.info("直接连接成功")
                    except Exception as retry_error:
                        logger.error(f"直接连接也失败: {str(retry_error)}")
                        # 恢复原始代理设置
                        session.proxies = original_proxies
                        raise
                    finally:
                        # 确保恢复原始代理设置
                        session.proxies = original_proxies
                
                except requests.exceptions.Timeout as timeout_error:
                    # 特别处理超时错误
                    logger.error(f"请求超时: {str(timeout_error)}")
                    logger.info("尝试增加超时时间后重试...")
                    
                    # 增加超时时间后重试
                    try:
                        response = session.get(url, timeout=(5, 10), headers=headers, stream=True)
                        response.raise_for_status()
                        response_text = response.text
                    except Exception as retry_error:
                        logger.error(f"增加超时后重试失败: {str(retry_error)}")
                        raise
                
                except requests.exceptions.RequestException as e:
                    # 记录详细的错误信息
                    error_msg = str(e)
                    if hasattr(e, 'response') and e.response is not None:
                        status_code = e.response.status_code
                        error_msg += f" (状态码: {status_code})"
                        
                        # 记录GitHub API限制相关的错误
                        if status_code == 429:
                            remaining = e.response.headers.get('X-RateLimit-Remaining', '未知')
                            reset = e.response.headers.get('X-RateLimit-Reset', '未知')
                            reset_time = datetime.fromtimestamp(int(reset)).strftime('%Y-%m-%d %H:%M:%S') if reset != '未知' and reset.isdigit() else '未知'
                            logger.error(f"GitHub API速率限制已达上限，剩余请求数: {remaining}，重置时间: {reset_time}")
                    
                    logger.error(f"从数据源 {source_name} 获取数据失败: {error_msg}")
                    
                    # 对于GitHub相关的429错误，等待一段时间后重试一次
                    if 'github.com' in url and '429' in error_msg:
                        logger.info("等待5秒后尝试重试...")
                        time.sleep(5)
                        try:
                            response = session.get(url, timeout=timeout, headers=headers, stream=True)
                            response.raise_for_status()
                            response_text = response.text
                        except requests.exceptions.RequestException as retry_e:
                            logger.error(f"重试失败: {str(retry_e)}")
                            raise
                    else:
                        raise
                
                # 处理不同格式的数据
                if is_markdown:
                    # 对于Markdown格式的数据源，需要特别处理
                    matched_items = self._search_cve_in_markdown(cve_id, response_text, source)
                else:
                    # 对于JSON格式的数据源，使用原有的处理方式
                    try:
                        data = json.loads(response_text)
                        matched_items = self._search_cve_in_data(cve_id, data)
                    except json.JSONDecodeError as e:
                        logger.error(f"解析JSON数据失败: {str(e)}")
                        continue
                
                # 添加到结果中（去重）
                for item in matched_items:
                    # 如果有full_name但没有url，构建GitHub仓库URL
                    if item.get('full_name') and not item.get('url'):
                        item['url'] = f"https://github.com/{item.get('full_name')}"
                    
                    # 如果有url和full_name，确保url是正确的GitHub仓库URL
                    elif item.get('full_name') and item.get('url') and 'github.com' not in item.get('url'):
                        item['url'] = f"https://github.com/{item.get('full_name')}"
                    
                    # 去重检查
                    item_url = item.get('url', '')
                    if item_url and item_url not in seen_urls:
                        seen_urls.add(item_url)
                        item['source'] = source_name
                        poc_items.append(item)
            except Exception as e:
                logger.error(f"从数据源 {source_name} 获取数据失败: {str(e)}")
                continue
        
        # 构建POC搜索结果
        poc_results = {
            'cve_id': cve_id,
            'has_poc': len(poc_items) > 0,
            'poc_items': poc_items,
            'sources': [s.get('name', 'Unknown') for s in sorted_sources],
            'search_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 保存到数据库和缓存，添加错误处理
        try:
            db_manager.update_poc_info(cve_id, json.dumps(poc_results))
        except Exception as e:
            logger.warning(f"更新数据库POC信息时出错: {str(e)}")
            
        # 无论数据库操作是否成功，都缓存结果
        cache_helper.cache_data(cache_key, poc_results)
        
        logger.info(f"CVE {cve_id} 的POC搜索完成，找到 {len(poc_items)} 个匹配结果")
        return poc_results
    
    def _search_cve_in_markdown(self, cve_id: str, markdown_text: str, source: Dict) -> List[Dict]:
        """在Markdown文本中搜索特定CVE
        
        Args:
            cve_id: CVE编号
            markdown_text: Markdown文本内容
            source: 数据源配置
        
        Returns:
            匹配的POC信息列表
        """
        results = []
        cve_id_lower = cve_id.lower()
        
        # 简单地在Markdown文本中搜索CVE ID
        if cve_id_lower not in markdown_text.lower():
            return results
        
        # 提取可能的URL和描述信息
        lines = markdown_text.split('\n')
        import re
        
        # 寻找CVE标题行
        cve_header_pattern = re.compile(f'##\\s+{re.escape(cve_id)}', re.IGNORECASE)
        cve_header_index = -1
        
        for i, line in enumerate(lines):
            if cve_header_pattern.search(line):
                cve_header_index = i
                break
        
        if cve_header_index == -1:
            # 如果没有找到明确的标题行，使用简单提取，但尝试提取有意义的描述
            poc_entry = {
                'name': f"{cve_id} POC/EXP",
                'description': "",
                'url': source.get('url', ''),
                'full_name': ''  # 初始化full_name字段
            }
            
            # 尝试在Markdown文本中提取与CVE相关的描述
            description_lines = []
            for i, line in enumerate(lines):
                line_lower = line.lower()
                if cve_id_lower in line_lower and len(line.strip()) > len(cve_id) + 5:
                    # 找到包含CVE ID的行，且该行有更多内容，可能是描述
                    description_lines.append(line.strip())
                    # 尝试收集接下来的几行作为描述
                    for j in range(i+1, min(i+3, len(lines))):
                        next_line = lines[j].strip()
                        if next_line and not next_line.startswith(('##', '- [', '* ')):
                            description_lines.append(next_line)
                    break
            
            # 如果收集到了描述行，合并为描述
            if description_lines:
                poc_entry['description'] = ' '.join(description_lines)
            else:
                # 如果没有找到有意义的描述，使用默认描述
                poc_entry['description'] = f"在 {source.get('name')} 中发现相关POC/EXP信息"
            
            # 尝试提取GitHub链接
            url_pattern = re.compile(r'http[s]?://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+')
            url_matches = url_pattern.finditer(markdown_text)
            
            for match in url_matches:
                poc_entry_copy = poc_entry.copy()
                poc_entry_copy['url'] = match.group(0)
                # 从URL中提取full_name
                url_parts = poc_entry_copy['url'].split('/')
                if len(url_parts) >= 5:
                    poc_entry_copy['full_name'] = f"{url_parts[3]}/{url_parts[4]}"
                results.append(poc_entry_copy)
            
            # 如果没有找到URL但找到了仓库路径
            if not results:
                repo_pattern = re.compile(r'[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+')
                repo_matches = repo_pattern.finditer(markdown_text)
                
                for match in repo_matches:
                    full_name = match.group(0)
                    poc_entry_copy = poc_entry.copy()
                    poc_entry_copy['full_name'] = full_name
                    poc_entry_copy['url'] = f"https://github.com/{full_name}"
                    results.append(poc_entry_copy)
        else:
            # 找到了CVE标题行，按照用户指定的格式提取信息
            # 1. 提取描述信息（CVE编号二级标题下的一段内容）
            description = ""
            # 收集标题行后面的第一个段落内容，直到遇到空行或下一个标题行
            description_lines = []
            for i in range(cve_header_index + 1, len(lines)):
                line = lines[i]
                # 检查是否遇到下一个标题行
                if line.strip().startswith('## '):
                    break
                # 如果遇到空行，说明第一个段落结束
                if not line.strip():
                    if description_lines:  # 如果已经收集了描述内容，则结束收集
                        break
                    else:  # 如果还没有收集到描述内容，则跳过空行
                        continue
                # 收集描述内容，保留原始格式
                description_lines.append(line.rstrip())
            
            # 将收集的行合并为描述，保持原始的换行格式
            if description_lines:
                description = '\n'.join(description_lines).strip()
            
            # 如果没有找到描述，使用默认描述
            if not description:
                description = f"在 {source.get('name')} 中发现相关POC/EXP信息"
            
            # 2. 提取特定格式的poc仓库链接: - [poc仓库](poc仓库): [star]、[fork]
            poc_repo_pattern = re.compile(r'-\s+\[(.*?)\]\((.*?)\):\s*\[star\]、\[fork\]')
            
            # 从标题行之后开始搜索特定格式的链接
            content_after_header = '\n'.join(lines[cve_header_index:])
            poc_repo_matches = poc_repo_pattern.finditer(content_after_header)
            
            for match in poc_repo_matches:
                repo_name = match.group(1)
                repo_url = match.group(2)
                
                # 确保URL是完整的GitHub仓库URL
                if not repo_url.startswith('http'):
                    # 检查是否已经包含用户名/仓库名格式
                    if '/' in repo_url:
                        repo_url = f"https://github.com/{repo_url}"
                    else:
                        continue  # 不是有效的仓库路径格式
                
                # 从URL中提取full_name
                url_parts = repo_url.split('/')
                full_name = f"{url_parts[3]}/{url_parts[4]}" if len(url_parts) >= 5 else repo_name
                
                poc_entry = {
                    'name': f"{cve_id} POC/EXP",
                    'description': description,
                    'url': repo_url,
                    'full_name': full_name
                }
                results.append(poc_entry)
                
            # 3. 如果没有找到特定格式的链接，回退到提取所有GitHub链接
            if not results:
                url_pattern = re.compile(r'http[s]?://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+')
                url_matches = url_pattern.finditer(content_after_header)
                
                for match in url_matches:
                    url = match.group(0)
                    # 从URL中提取full_name
                    url_parts = url.split('/')
                    full_name = f"{url_parts[3]}/{url_parts[4]}" if len(url_parts) >= 5 else ""
                    
                    poc_entry = {
                        'name': f"{cve_id} POC/EXP",
                        'description': description,
                        'url': url,
                        'full_name': full_name
                    }
                    results.append(poc_entry)
        
        return results
        
    def _search_cve_in_data(self, cve_id: str, data) -> List[Dict]:
        """在数据中搜索特定CVE"""
        results = []
        cve_id_lower = cve_id.lower()
        
        # 根据数据结构类型进行搜索
        if isinstance(data, dict):
            # 检查是否有'new'字段（如update.json的结构）
            if 'new' in data and isinstance(data['new'], list):
                for item in data['new']:
                    if self._is_cve_match(cve_id_lower, item):
                        results.append(self._extract_poc_info(item))
            # 检查是否为直接的仓库列表
            elif isinstance(data.get('items'), list):
                for item in data['items']:
                    if self._is_cve_match(cve_id_lower, item):
                        results.append(self._extract_poc_info(item))
            else:
                # 尝试直接搜索整个字典
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            if self._is_cve_match(cve_id_lower, item):
                                results.append(self._extract_poc_info(item))
        elif isinstance(data, list):
            # 直接遍历列表
            for item in data:
                if self._is_cve_match(cve_id_lower, item):
                    results.append(self._extract_poc_info(item))
        
        return results
        
    def _is_cve_match(self, cve_id_lower: str, item) -> bool:
        """检查项目是否匹配CVE ID"""
        if not isinstance(item, dict):
            return False
        
        # 检查项目名称、全名或描述中是否包含CVE ID
        name = item.get('name', '').lower()
        full_name = item.get('full_name', '').lower()
        description = item.get('description', '').lower()
        
        return cve_id_lower in name or cve_id_lower in full_name or cve_id_lower in description
        
    def _extract_poc_info(self, item: Dict) -> Dict:
        """从项目中提取POC信息"""
        # 获取full_name，优先使用item中的full_name
        full_name = item.get('full_name', '')
        
        # 获取URL，优先使用html_url，然后是url，最后基于full_name构建
        url = item.get('html_url', '')
        if not url:
            url = item.get('url', '')
        if not url and full_name:
            url = f"https://github.com/{full_name}"
        
        # 获取描述信息，优先使用item中的description
        description = item.get('description', 'No description')
        
        
        
        poc_info = {
            'name': item.get('name', full_name if full_name else ''),
            'full_name': full_name,
            'description': description,
            'url': url
        }
        
        # 添加其他可能的字段
        if 'topics' in item:
            poc_info['topics'] = item['topics']
        if 'type' in item:
            poc_info['type'] = item['type']
        
        return poc_info
    

    
    
    # 合并和排序相关方法已删除
    
    def check_cve_has_poc(self, cve_id: str) -> bool:
        """检查指定的CVE是否有可用的POC
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            bool: 是否有POC
        """
        poc_info = self.search_poc_for_cve(cve_id)
        return poc_info.get('has_poc', False)
    
    def process_single_cve(self, cve_data: Dict) -> Dict:
        """处理单个CVE数据
        
        Args:
            cve_data: CVE数据
        
        Returns:
            处理后的CVE数据
        """
        cve_id = cve_data.get('cve_id')
        if not cve_id:
            return cve_data
        
        # 搜索POC信息
        poc_info = self.search_poc_for_cve(cve_id)
        cve_data['poc_info'] = poc_info
        
        # 如果找到POC，添加特殊标签
        if poc_info.get('has_poc', False):
            # 使用CVE处理器的原逻辑进行标签处理
            tags = cve_data.get('tags', [])
            if not isinstance(tags, list):
                tags = tags.split(',') if isinstance(tags, str) else []
            
            # 添加POC相关标签
            severity_found = False
            updated_tags = []
            for tag in tags:
                tag_lower = tag.lower()
                if tag_lower in ['critical', '严重', 'high', '高危']:
                    updated_tags.append(f"{tag}(存在poc/exp)")
                    severity_found = True
                else:
                    updated_tags.append(tag)
            
            # 如果没有严重/高危标签，添加通用的POC标签
            if not severity_found and '存在poc/exp' not in updated_tags:
                updated_tags.append('存在poc/exp')
            
            # 去重并更新标签
            cve_data['tags'] = list(set(updated_tags))
        
        # 使用CVE处理器处理数据
        processed_data = self.cve_processor.process_cve(cve_data)
        
        return processed_data
        
    def process_today_vulns(self):
        """处理当天的漏洞信息"""
        processed_vulns = []
        
        # 检查标志文件
        if not os.path.exists(self.new_vulns_flag):
            logger.info("没有新的漏洞需要处理")
            return processed_vulns
        
        logger.info("开始处理当天的漏洞信息")
        
        # 读取新漏洞标志文件
        try:
            with open(self.new_vulns_flag, 'r', encoding='utf-8') as f:
                vulns_data = json.load(f)
            
            # 获取当天的漏洞
            today = datetime.now().strftime('%Y-%m-%d')
            today_vulns = vulns_data.get(today, [])
            
            if not today_vulns:
                logger.info(f"{today} 没有发现新漏洞")
                return processed_vulns
            
            # 处理每个漏洞
            for vuln in today_vulns:
                processed_vuln = self.process_single_cve(vuln)
                processed_vulns.append(processed_vuln)
            
            # 更新漏洞数据
            vulns_data[today] = processed_vulns
            
            # 写回标志文件
            with open(self.new_vulns_flag, 'w', encoding='utf-8') as f:
                json.dump(vulns_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"成功处理了 {len(processed_vulns)} 个漏洞")
        except Exception as e:
            logger.error(f"处理当天漏洞时出错: {str(e)}")
        
        return processed_vulns
    
    def run_daily_check(self):
        """运行每日检查"""
        logger.info("开始执行每日POC检查任务")
        processed_count = 0
        
        try:
            # 处理当天的漏洞（通过标志文件）
            processed_vulns = self.process_today_vulns()
            
            # 如果返回了处理的漏洞列表，则获取数量
            if processed_vulns:
                processed_count = len(processed_vulns)
            
            # 额外从数据库中获取当天已存在的漏洞数量（用于统计）
            from src.utils.db_manager import db_manager
            db_vulns = db_manager.get_today_vulnerabilities()
            if db_vulns:
                db_count = len(db_vulns)
                # 如果数据库中的漏洞数量大于通过标志文件处理的数量，则使用数据库中的数量
                if db_count > processed_count:
                    processed_count = db_count
                    logger.info(f"从数据库中检测到 {db_count} 个当天漏洞")
                
                # 创建或更新标志文件
                today = datetime.now().strftime('%Y-%m-%d')
                vulns_data = {}
                
                # 如果标志文件已存在，读取现有内容
                if os.path.exists(self.new_vulns_flag):
                    try:
                        with open(self.new_vulns_flag, 'r', encoding='utf-8') as f:
                            vulns_data = json.load(f)
                    except:
                        vulns_data = {}
                
                # 更新今天的漏洞数据
                vulns_data[today] = db_vulns
                
                # 确保data目录存在
                os.makedirs(os.path.dirname(self.new_vulns_flag), exist_ok=True)
                
                # 写回标志文件
                with open(self.new_vulns_flag, 'w', encoding='utf-8') as f:
                    json.dump(vulns_data, f, ensure_ascii=False, indent=2)
                
                logger.info(f"已更新新漏洞标志文件，包含 {db_count} 个漏洞")
            
            logger.info("每日POC检查任务执行完成")
        except Exception as e:
            logger.error(f"执行每日检查时出错: {str(e)}")
            
        return processed_count
        
    def start_monitoring(self):
        """启动监控服务"""
        logger.info(f"启动POC监控服务，检查间隔: {self.check_interval}秒")
        
        try:
            while True:
                try:
                    # 运行检查
                    self.run_daily_check()
                    logger.info(f"检查完成，等待 {self.check_interval} 秒后再次检查")
                except Exception as e:
                    logger.error(f"检查过程中发生错误: {str(e)}")
                    # 错误发生后仍然继续运行
                
                # 等待指定的时间间隔
                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            logger.info("POC监控服务被用户中断")
        except Exception as e:
            logger.error(f"POC监控服务异常: {str(e)}")
            raise

    def generate_daily_report(self, date=None):
        """生成每日漏洞报告
        
        Args:
            date: 日期（格式：YYYY-MM-DD），默认为当天
            
        Returns:
            str: 报告文件路径
        """
        try:
            logger.info(f"开始生成每日报告，日期: {date or '当天'}")
            
            # 确定要查询的日期
            if not date:
                today = datetime.now().strftime('%Y-%m-%d')
            else:
                today = date
            
            # 创建报告目录
            report_dir = os.path.join('data', str(datetime.now().year), f"W{datetime.now().isocalendar()[1]:02d}-{today.replace('-', '')[-4:]}")
            if not os.path.exists(report_dir):
                os.makedirs(report_dir)
            
            # 从数据库获取指定日期的漏洞信息
            # 这里需要导入db_manager，避免循环导入
            from src.utils.db_manager import db_manager
            if date:
                # 如果指定了日期，使用get_vulnerabilities_by_date方法
                today_vulns = db_manager.get_vulnerabilities_by_date(date)
            else:
                # 否则使用get_today_vulnerabilities方法
                today_vulns = db_manager.get_today_vulnerabilities()
            
            if not today_vulns:
                logger.info(f"{today} 没有找到漏洞信息")
                return None
            
            # 生成报告内容
            report_content = self._generate_report_content(today_vulns, today)
            
            # 保存报告文件
            report_path = os.path.join(report_dir, 'daily.md')
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            logger.info(f"每日报告生成成功: {report_path}")
            return report_path
        except Exception as e:
            logger.error(f"生成每日报告时出错: {str(e)}")
            return None
            
    def _generate_report_content(self, vulns, date):
        """生成报告内容
        
        Args:
            vulns: 漏洞列表
            date: 日期
            
        Returns:
            str: 报告内容
        """
        # 报告标题
        content = [f"# {date} 漏洞日报"]
        content.append("")
        
        # 概述部分
        content.append("## 概述")
        content.append(f"- 总漏洞数量: {len(vulns)}")
        
        # 计算最高CVSS评分
        max_cvss = max([vuln[5] for vuln in vulns if vuln[5] is not None], default=0)
        content.append(f"- 最高CVSS评分: {max_cvss}")
        content.append(f"- 统计时间: {date} (UTC)")
        content.append("")
        
        # 严重漏洞部分 (CVSS ≥ 9.0)
        critical_vulns = [v for v in vulns if v[5] and v[5] >= 9.0]
        if critical_vulns:
            content.append(f"## 严重漏洞 (CVSS ≥ 9.0) [共{len(critical_vulns)}个]")
            content.append("")
            
            # 按CVSS评分降序排序
            critical_vulns.sort(key=lambda x: x[5], reverse=True)
            
            # 遍历每个漏洞
            for vuln in critical_vulns:
                self._add_vuln_details(content, vuln)
        
        # 高危漏洞部分 (7.0 ≤ CVSS < 9.0)
        high_vulns = [v for v in vulns if v[5] and 7.0 <= v[5] < 9.0]
        if high_vulns:
            content.append(f"## 高危漏洞 (7.0 ≤ CVSS < 9.0) [共{len(high_vulns)}个]")
            content.append("")
            
            # 按CVSS评分降序排序
            high_vulns.sort(key=lambda x: x[5], reverse=True)
            
            # 遍历每个漏洞
            for vuln in high_vulns:
                self._add_vuln_details(content, vuln)
        
        # 中危和低危漏洞部分 (CVSS < 7.0) - 仅显示数量统计
        medium_low_vulns = [v for v in vulns if v[5] and v[5] < 7.0]
        if medium_low_vulns:
            content.append(f"## 中低危漏洞 (CVSS < 7.0) [共{len(medium_low_vulns)}个]")
            content.append("（注：本报告仅显示高危及以上级别漏洞的详细信息）")
            content.append("")
        
        # 数据来源部分
        content.append("## 数据来源")
        content.append("- NVD (National Vulnerability Database)")
        content.append("")
        
        # 报告生成时间
        content.append("---")
        content.append(f"*本报告由 CVE Push Service 自动生成*")
        
        return '\n'.join(content)
        
    def _add_vuln_details(self, content, vuln):
        """向报告内容中添加漏洞详细信息
        
        Args:
            content: 报告内容列表
            vuln: 漏洞数据
        """
        cve_id = vuln[0]
        description = vuln[1] or "暂无描述"
        severity = vuln[2] or "未知"
        published_date = vuln[3] or "未知"
        cvss_score = vuln[5] or "未知"
        
        # 添加漏洞标题和基本信息
        content.append(f"### {cve_id} - CVSS: {cvss_score}")
        content.append("")
        content.append(f"**发布时间**: {published_date}")
        content.append(f"**漏洞分类**: {severity}")
        content.append("")
        
        # 添加漏洞描述
        content.append("#### 漏洞描述")
        # 限制描述长度，避免过长
        if len(description) > 500:
            description = description[:500] + "..."
        content.append(description)
        content.append("")
        
        # 添加相关链接
        content.append("#### 相关链接")
        
        # 尝试从数据库中获取实际的引用链接
        try:
            # vuln_references是JSON字符串格式存储的
            references_json = vuln[6]  # vuln_references在数据库中的索引位置是6
            if references_json:
                references = json.loads(references_json)
                if references and isinstance(references, list):
                    for ref in references[:5]:  # 限制显示最多5个链接
                        # 按照旧脚本的逻辑，将链接格式化为Markdown格式
                        if isinstance(ref, dict):
                            url = ref.get('url', '')
                            source = ref.get('source', '').strip()
                            if url:
                                # 如果有source且不为空，使用source作为链接文本
                                if source:
                                    content.append(f"- [{source}]({url})")
                                else:
                                    # 否则直接使用URL作为链接文本
                                    content.append(f"- [{url}]({url})")
                        elif isinstance(ref, str) and ref.startswith('http'):
                            # 如果ref已经是一个URL字符串
                            content.append(f"- [{ref}]({ref})")
                else:
                    # 如果引用为空或格式不正确，显示默认链接
                    content.append(f"- [NVD详情](https://nvd.nist.gov/vuln/detail/{cve_id})")
            else:
                # 如果没有引用信息，显示默认链接
                content.append(f"- [NVD详情](https://nvd.nist.gov/vuln/detail/{cve_id})")
        except (json.JSONDecodeError, IndexError, Exception):
            # 处理解析错误，显示默认链接
            content.append(f"- [NVD详情](https://nvd.nist.gov/vuln/detail/{cve_id})")
        
        content.append("")
    
    # 移除不需要的方法

    def main(self):
        """主函数入口"""
        # 运行每日检查
        self.run_daily_check()
        
        # 可以在这里添加其他操作
        logger.info("POC监控工具主函数执行完毕")

# 创建默认实例
poc_monitor = PocMonitor()