import logging
import os
import json
import re
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

from src.config import settings
from src.utils.db_manager import db_manager
from src.utils.cache_helper import cache_helper
from src.utils.file_helper import file_helper
from src.utils.translation_helper import translation_helper
from src.utils.date_helper import date_helper
from src.core.cve_collector import cve_collector
from src.core.cve_processor import cve_processor

logger = logging.getLogger(__name__)

class PocMonitor:
    """POC监控类，负责监控和收集CVE相关的POC信息"""
    
    def __init__(self):
        """初始化POC监控"""
        # 从配置获取设置
        self.new_vulns_flag = settings.get('POC_MONITOR.new_vulns_flag', 'data/new_vulns.flag')
        self.check_interval = settings.get('POC_MONITOR.check_interval', 3600)
        self.max_workers = 5  # 并发工作线程数
        
        # POC来源权重（用于排序）
        self.source_weights = {
            'github': 10,
            'exploit_db': 9,
            'nvd': 8,
            'cve_detail': 7,
            'seebug': 6,
            'wooyun': 5,
            'packetstorm': 4,
            'other': 3
        }
    
    def search_poc_for_cve(self, cve_id: str) -> Dict:
        """为指定的CVE搜索POC信息
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            Dict: POC信息字典
        """
        if not cve_id.startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        
        logger.info(f"开始搜索CVE的POC信息: {cve_id}")
        
        # 检查缓存
        cache_key = f'poc_{cve_id.lower()}'
        cached_poc = cache_helper.get_cached_data(cache_key)
        if cached_poc:
            logger.debug(f"从缓存获取POC信息: {cve_id}")
            return cached_poc
        
        # 从数据库检查
        cve_data = db_manager.get_cve_info(cve_id)
        if cve_data and cve_data[10]:  # poc_info字段
            try:
                poc_info = json.loads(cve_data[10])
                if poc_info:
                    logger.debug(f"从数据库获取POC信息: {cve_id}")
                    return poc_info
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"解析数据库中的POC信息失败: {cve_id}")
        
        # 搜索各个源的POC信息
        poc_results = []
        
        # 使用线程池并发搜索多个源
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交搜索任务
            future_to_source = {
                executor.submit(self._search_github_poc, cve_id): 'github',
                executor.submit(self._search_exploit_db_poc, cve_id): 'exploit_db',
                executor.submit(self._search_seebug_poc, cve_id): 'seebug',
                executor.submit(self._search_packetstorm_poc, cve_id): 'packetstorm',
                executor.submit(self._search_wooyun_poc, cve_id): 'wooyun'
            }
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result()
                    if result:
                        poc_results.extend(result)
                except Exception as e:
                    logger.error(f"从{source}搜索POC时发生错误: {str(e)}")
        
        # 合并和排序POC结果
        poc_info = self._merge_and_rank_poc_results(poc_results)
        
        # 缓存结果
        cache_helper.cache_data(cache_key, poc_info)
        
        logger.info(f"完成POC搜索，找到 {len(poc_results)} 个结果: {cve_id}")
        return poc_info
    
    def _search_github_poc(self, cve_id: str) -> List[Dict]:
        """从GitHub搜索POC信息
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            List[Dict]: POC信息列表
        """
        results = []
        
        try:
            # 构建GitHub API搜索URL
            github_api_url = settings.get('API.github.base_url', 'https://api.github.com/')
            search_url = f"{github_api_url}search/repositories"
            
            # 准备请求参数
            params = {
                'q': f'{cve_id} exploit poc',
                'sort': 'stars',
                'order': 'desc',
                'per_page': 10
            }
            
            # 添加GitHub token（如果有）
            headers = {'User-Agent': settings.get('APP.user_agent', 'Mozilla/5.0')}
            github_token = settings.get('API.github.token', '')
            if github_token:
                headers['Authorization'] = f'token {github_token}'
            
            # 发送请求
            response = requests.get(search_url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get('items', []):
                    # 提取相关信息
                    poc_item = {
                        'source': 'github',
                        'title': item.get('name', ''),
                        'description': item.get('description', ''),
                        'url': item.get('html_url', ''),
                        'stars': item.get('stargazers_count', 0),
                        'forks': item.get('forks_count', 0),
                        'created_at': item.get('created_at', ''),
                        'updated_at': item.get('updated_at', ''),
                        'type': 'repository',
                        'weight': self.source_weights.get('github', 10)
                    }
                    
                    # 计算分数（权重 * 星数的对数）
                    poc_item['score'] = poc_item['weight'] * (1 + (poc_item['stars'] ** 0.5))
                    
                    results.append(poc_item)
            else:
                logger.warning(f"GitHub API请求失败，状态码: {response.status_code}")
        except Exception as e:
            logger.error(f"从GitHub搜索POC时发生异常: {str(e)}")
        
        return results
    
    def _search_exploit_db_poc(self, cve_id: str) -> List[Dict]:
        """从Exploit-DB搜索POC信息
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            List[Dict]: POC信息列表
        """
        results = []
        
        try:
            # 构建Exploit-DB搜索URL
            exploit_db_base_url = settings.get('API.exploit_db.base_url', 'https://www.exploit-db.com/')
            search_url = f"{exploit_db_base_url}search"
            
            # 准备请求参数
            params = {
                'cve': cve_id,
                'type': 'remote'
            }
            
            # 发送请求
            headers = {'User-Agent': settings.get('APP.user_agent', 'Mozilla/5.0')}
            response = requests.get(search_url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # 这里简化处理，实际应该解析HTML获取数据
                # 由于Exploit-DB没有公开的API，这里使用一个模拟结果
                # 在实际应用中，应该使用BeautifulSoup等库解析HTML
                logger.debug(f"Exploit-DB搜索结果获取成功: {cve_id}")
                # 注意：以下为模拟数据，实际应用中需要替换为HTML解析代码
                # 这部分需要根据Exploit-DB的实际页面结构进行调整
                # 由于没有实际API，这里我们不添加实际结果
        except Exception as e:
            logger.error(f"从Exploit-DB搜索POC时发生异常: {str(e)}")
        
        return results
    
    def _search_seebug_poc(self, cve_id: str) -> List[Dict]:
        """从Seebug搜索POC信息
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            List[Dict]: POC信息列表
        """
        results = []
        
        try:
            # Seebug API或搜索逻辑
            # 注意：Seebug可能需要认证或有访问限制
            logger.debug(f"尝试从Seebug搜索POC: {cve_id}")
            # 这里简化处理，实际应用中需要根据Seebug的API或页面结构进行调整
        except Exception as e:
            logger.error(f"从Seebug搜索POC时发生异常: {str(e)}")
        
        return results
    
    def _search_packetstorm_poc(self, cve_id: str) -> List[Dict]:
        """从PacketStorm搜索POC信息
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            List[Dict]: POC信息列表
        """
        results = []
        
        try:
            # PacketStorm搜索逻辑
            logger.debug(f"尝试从PacketStorm搜索POC: {cve_id}")
            # 这里简化处理，实际应用中需要根据PacketStorm的页面结构进行调整
        except Exception as e:
            logger.error(f"从PacketStorm搜索POC时发生异常: {str(e)}")
        
        return results
    
    def _search_wooyun_poc(self, cve_id: str) -> List[Dict]:
        """从Wooyun搜索POC信息
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            List[Dict]: POC信息列表
        """
        results = []
        
        try:
            # Wooyun搜索逻辑
            logger.debug(f"尝试从Wooyun搜索POC: {cve_id}")
            # 这里简化处理，实际应用中需要根据Wooyun的页面结构进行调整
        except Exception as e:
            logger.error(f"从Wooyun搜索POC时发生异常: {str(e)}")
        
        return results
    
    def _merge_and_rank_poc_results(self, poc_results: List[Dict]) -> Dict:
        """合并并排序POC结果
        
        Args:
            poc_results: POC结果列表
            
        Returns:
            Dict: 处理后的POC信息
        """
        # 去重 - 根据URL
        unique_results = []
        seen_urls = set()
        
        for result in poc_results:
            url = result.get('url', '')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(result)
        
        # 根据分数排序
        sorted_results = sorted(unique_results, key=lambda x: x.get('score', 0), reverse=True)
        
        # 构建返回数据
        poc_info = {
            'total': len(sorted_results),
            'results': sorted_results,
            'top_result': sorted_results[0] if sorted_results else None,
            'has_poc': len(sorted_results) > 0,
            'last_updated': datetime.now().isoformat()
        }
        
        return poc_info
    
    def check_cve_has_poc(self, cve_id: str) -> bool:
        """检查指定的CVE是否有可用的POC
        
        Args:
            cve_id: CVE标识符
            
        Returns:
            bool: 是否有POC
        """
        poc_info = self.search_poc_for_cve(cve_id)
        return poc_info.get('has_poc', False)
    
    def process_today_vulns(self) -> List[Dict]:
        """处理当天的漏洞
        
        Returns:
            List[Dict]: 处理后的漏洞列表
        """
        logger.info("开始处理当天的漏洞")
        
        # 检查是否有new_vulns.flag文件
        if os.path.exists(self.new_vulns_flag):
            try:
                # 读取当天的新漏洞列表
                with open(self.new_vulns_flag, 'r', encoding='utf-8') as f:
                    cve_ids = [line.strip() for line in f if line.strip()]
                
                logger.info(f"读取到 {len(cve_ids)} 个新漏洞ID")
                
                # 处理每个漏洞
                processed_vulns = []
                for cve_id in cve_ids:
                    try:
                        # 获取CVE信息
                        cve_data = cve_collector.get_cve_by_id(cve_id)
                        if not cve_data:
                            logger.warning(f"未找到CVE信息: {cve_id}")
                            continue
                        
                        # 搜索POC信息
                        poc_info = self.search_poc_for_cve(cve_id)
                        cve_data['poc_info'] = poc_info
                        
                        # 处理CVE数据
                        processed_cve = cve_processor.process_cve(cve_data)
                        processed_vulns.append(processed_cve)
                        
                        # 更新数据库中的POC信息
                        db_manager.update_poc_info(cve_id, json.dumps(poc_info))
                    except Exception as e:
                        logger.error(f"处理漏洞时发生错误: {cve_id}, 错误: {str(e)}")
                
                # 删除flag文件，表示已处理
                os.remove(self.new_vulns_flag)
                logger.info("已删除new_vulns.flag文件")
                
                return processed_vulns
            except Exception as e:
                logger.error(f"处理当天漏洞时发生错误: {str(e)}")
                return []
        else:
            logger.info("未找到new_vulns.flag文件，无需处理")
            return []
    
    def run_daily_check(self) -> List[Dict]:
        """执行每日检查
        
        Returns:
            List[Dict]: 当天发现的新漏洞列表
        """
        logger.info("开始执行每日CVE检查")
        
        try:
            # 获取当天的漏洞
            today = datetime.now().strftime('%Y-%m-%d')
            recent_cves = cve_collector.get_recent_cves(days=1, start_date=today, end_date=today)
            
            logger.info(f"获取到 {len(recent_cves)} 个当天的漏洞")
            
            # 将新漏洞ID写入flag文件
            if recent_cves:
                cve_ids = [cve.get('id', '') for cve in recent_cves if cve.get('id')]
                with open(self.new_vulns_flag, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(cve_ids))
                
                logger.info(f"已将 {len(cve_ids)} 个新漏洞ID写入flag文件")
            
            # 处理新漏洞
            processed_vulns = self.process_today_vulns()
            
            logger.info(f"每日检查完成，共处理 {len(processed_vulns)} 个漏洞")
            return processed_vulns
        except Exception as e:
            logger.error(f"执行每日检查时发生错误: {str(e)}")
            return []
    
    def start_monitoring(self) -> None:
        """启动持续监控模式"""
        logger.info("POC监控服务已启动")
        
        try:
            while True:
                # 执行每日检查
                self.run_daily_check()
                
                # 等待下一次检查
                logger.info(f"等待 {self.check_interval} 秒后进行下一次检查")
                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            logger.info("POC监控服务已停止")
        except Exception as e:
            logger.error(f"监控服务发生错误: {str(e)}")
    
    def generate_daily_report(self, date: Optional[str] = None) -> Optional[str]:
        """生成每日报告
        
        Args:
            date: 日期（格式：YYYY-MM-DD），默认为当天
            
        Returns:
            Optional[str]: 报告文件路径
        """
        try:
            if not date:
                date = datetime.now().strftime('%Y-%m-%d')
            
            logger.info(f"开始生成 {date} 的每日报告")
            
            # 从数据库获取当天的漏洞
            vulns = db_manager.get_vulnerabilities_by_date(date)
            
            if not vulns:
                logger.info(f"未找到 {date} 的漏洞信息")
                return None
            
            # 构建报告内容
            report_content = []
            report_content.append(f"# {date} CVE漏洞日报")
            report_content.append("")
            report_content.append(f"## 概览")
            report_content.append(f"- 共发现 {len(vulns)} 个新漏洞")
            
            # 按严重性统计
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'None': 0}
            
            for vuln in vulns:
                severity = vuln[2]  # severity字段
                if severity in severity_count:
                    severity_count[severity] += 1
                else:
                    severity_count['None'] += 1
            
            # 添加统计信息
            for level, count in severity_count.items():
                if count > 0:
                    report_content.append(f"- {level}: {count} 个")
            
            report_content.append("")
            report_content.append("## 漏洞详情")
            report_content.append("")
            
            # 添加每个漏洞的简要信息
            for vuln in vulns:
                cve_id, description, severity, published_date, _, cvss_score, _, tags_json, _, _, poc_info_json, _ = vuln
                
                # 解析标签和POC信息
                try:
                    tags = json.loads(tags_json) if tags_json else []
                except (json.JSONDecodeError, TypeError):
                    tags = []
                
                try:
                    poc_info = json.loads(poc_info_json) if poc_info_json else {}
                except (json.JSONDecodeError, TypeError):
                    poc_info = {}
                
                # 添加漏洞信息
                report_content.append(f"### {cve_id}")
                report_content.append(f"- **严重性**: {severity}")
                if cvss_score:
                    report_content.append(f"- **CVSS评分**: {cvss_score}")
                report_content.append(f"- **发布日期**: {published_date}")
                if tags:
                    report_content.append(f"- **标签**: {', '.join(tags)}")
                if poc_info.get('has_poc', False):
                    report_content.append(f"- **POC状态**: 有可用POC")
                else:
                    report_content.append(f"- **POC状态**: 暂无POC")
                report_content.append(f"- **简要描述**: {description[:100]}...")
                report_content.append("")
            
            # 生成报告文件
            report_filename = f"daily_report_{date}.md"
            report_path = os.path.join(settings.get('POC_MONITOR.report_dir', 'data/reports'), report_filename)
            
            # 写入文件
            file_helper.write_file(report_path, '\n'.join(report_content))
            
            logger.info(f"已生成每日报告: {report_path}")
            return report_path
        except Exception as e:
            logger.error(f"生成每日报告时发生错误: {str(e)}")
            return None

# 创建默认实例
poc_monitor = PocMonitor()