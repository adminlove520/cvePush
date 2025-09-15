import logging
import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union

from src.config import settings
from src.utils.file_helper import file_helper
from src.utils.translation_helper import translation_helper
from src.utils.date_helper import date_helper
from src.utils.notification_helper import notification_manager

logger = logging.getLogger(__name__)

class CVEProcessor:
    """CVE信息处理器"""
    
    def __init__(self):
        """初始化CVE处理器"""
        # 从配置获取设置
        self.report_dir = settings.get('POC_MONITOR.report_dir', 'data/reports')
        self.enable_translation = settings.get('TRANSLATION.enabled', True)
        self.default_language = settings.get('TRANSLATION.default_language', 'zh')
        
        # 确保报告目录存在
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def process_cve(self, cve_data: Dict) -> Dict:
        """处理单个CVE数据
        
        Args:
            cve_data: CVE信息
            
        Returns:
            Dict: 处理后的CVE信息
        """
        try:
            logger.info(f"开始处理CVE: {cve_data.get('id', '未知')}")
            
            # 复制数据以避免修改原始数据
            processed_data = cve_data.copy()
            
            # 标准化日期格式
            self._normalize_dates(processed_data)
            
            # 处理描述（包括翻译）
            self._process_description(processed_data)
            
            # 提取标签
            self._extract_tags(processed_data)
            
            # 处理参考链接
            self._process_references(processed_data)
            
            # 计算严重性等级
            self._calculate_severity_level(processed_data)
            
            # 生成报告
            report_path = self.generate_report(processed_data)
            if report_path:
                processed_data['report_path'] = report_path
            
            # 发送通知
            if processed_data.get('is_new', False):
                self.send_notification(processed_data)
            
            logger.info(f"完成处理CVE: {processed_data.get('id', '未知')}")
            return processed_data
        except Exception as e:
            logger.error(f"处理CVE时发生错误: {str(e)}", exc_info=True)
            return cve_data
    
    def _normalize_dates(self, cve_data: Dict) -> None:
        """标准化日期格式
        
        Args:
            cve_data: CVE信息
        """
        date_fields = ['published_date', 'last_modified_date', 'created_at']
        
        for field in date_fields:
            if field in cve_data and cve_data[field]:
                try:
                    # 尝试解析各种日期格式
                    date_obj = date_helper.parse_datetime(cve_data[field])
                    if date_obj:
                        cve_data[field] = date_obj.isoformat()
                except Exception as e:
                    logger.warning(f"解析日期失败 ({field}): {str(e)}")
    
    def _process_description(self, cve_data: Dict) -> None:
        """处理描述文本
        
        Args:
            cve_data: CVE信息
        """
        if 'description' in cve_data and cve_data['description']:
            # 清理描述文本
            description = cve_data['description'].strip()
            description = re.sub(r'\s+', ' ', description)  # 替换多个空格为单个空格
            
            # 检查是否需要翻译
            if self.enable_translation:
                try:
                    # 检测源语言
                    source_lang = translation_helper.detect_language(description)
                    
                    # 如果源语言不是目标语言，进行翻译
                    if source_lang != self.default_language:
                        translated = translation_helper.translate(
                                description,
                                self.default_language
                            )
                        if translated:
                            cve_data['translated_description'] = translated
                            logger.debug(f"已翻译CVE描述: {cve_data.get('id', '未知')}")
                except Exception as e:
                    logger.warning(f"翻译CVE描述失败: {str(e)}")
            
            cve_data['description'] = description
    
    def _extract_tags(self, cve_data: Dict) -> None:
        """从描述和参考信息中提取标签
        
        Args:
            cve_data: CVE信息
        """
        tags = set(cve_data.get('tags', []))
        
        # 从严重性提取标签
        if 'severity' in cve_data and cve_data['severity']:
            tags.add(cve_data['severity'].lower())
        
        # 从描述提取关键词作为标签
        keywords = self._extract_keywords(cve_data.get('description', ''))
        tags.update(keywords)
        
        # 从参考链接提取标签
        if 'references' in cve_data:
            for ref in cve_data['references']:
                if isinstance(ref, dict) and 'url' in ref:
                    url = ref['url'].lower()
                    if 'github' in url:
                        tags.add('github')
                    if 'exploit-db' in url:
                        tags.add('exploit-db')
                    if 'nvd' in url:
                        tags.add('nvd')
        
        # 从POC信息提取标签
        if 'poc_info' in cve_data and cve_data['poc_info']:
            tags.add('has_poc')
            # 检查POC类型
            poc_type = cve_data['poc_info'].get('type', '').lower()
            if poc_type:
                tags.add(poc_type)
        
        # 转换为列表并更新
        cve_data['tags'] = list(tags)
    
    def _extract_keywords(self, text: str, max_keywords: int = 10) -> List[str]:
        """从文本中提取关键词
        
        Args:
            text: 输入文本
            max_keywords: 最大关键词数量
            
        Returns:
            List[str]: 关键词列表
        """
        # 常见的安全关键词
        security_keywords = {
            'sql injection', 'xss', 'cross-site', 'csrf', 'command injection',
            'buffer overflow', 'heap overflow', 'stack overflow', 'denial of service',
            'dos', 'remote code execution', 'rce', 'arbitrary code execution',
            'privilege escalation', 'unauthorized access', 'information disclosure',
            'directory traversal', 'path traversal', 'file inclusion', 'deserialization',
            'authentication bypass', 'authorization bypass', 'cryptographic flaw',
            'session fixation', 'clickjacking', 'phishing', 'malware', 'virus',
            'trojan', 'ransomware', 'zero-day', '0-day', 'vulnerability', 'exploit',
            'poc', 'proof of concept'
        }
        
        keywords = []
        text_lower = text.lower()
        
        for keyword in security_keywords:
            if keyword in text_lower:
                # 使用关键词的标准化形式
                if keyword == 'dos':
                    keywords.append('denial_of_service')
                elif keyword == 'rce':
                    keywords.append('remote_code_execution')
                elif keyword == '0-day':
                    keywords.append('zero_day')
                else:
                    keywords.append(keyword.replace(' ', '_'))
                
            # 达到最大数量时停止
            if len(keywords) >= max_keywords:
                break
        
        return keywords
    
    def _process_references(self, cve_data: Dict) -> None:
        """处理参考链接
        
        Args:
            cve_data: CVE信息
        """
        if 'references' in cve_data:
            processed_refs = []
            
            for ref in cve_data['references']:
                if isinstance(ref, dict):
                    # 确保url字段存在
                    if 'url' in ref and ref['url']:
                        processed_ref = ref.copy()
                        # 标准化URL
                        url = processed_ref['url'].strip()
                        if not url.startswith(('http://', 'https://')):
                            url = f'https://{url}'
                        processed_ref['url'] = url
                        processed_refs.append(processed_ref)
                elif isinstance(ref, str):
                    # 处理字符串形式的参考链接
                    url = ref.strip()
                    if not url.startswith(('http://', 'https://')):
                        url = f'https://{url}'
                    processed_refs.append({'url': url, 'source': '', 'tags': []})
            
            # 去重
            unique_refs = []
            seen_urls = set()
            for ref in processed_refs:
                if ref['url'] not in seen_urls:
                    seen_urls.add(ref['url'])
                    unique_refs.append(ref)
            
            cve_data['references'] = unique_refs
    
    def _calculate_severity_level(self, cve_data: Dict) -> None:
        """计算严重性等级
        
        Args:
            cve_data: CVE信息
        """
        if 'cvss_score' in cve_data and cve_data['cvss_score'] is not None:
            score = cve_data['cvss_score']
            
            # CVSS v3 评分标准
            if score >= 9.0:
                severity_level = 'Critical'
            elif score >= 7.0:
                severity_level = 'High'
            elif score >= 4.0:
                severity_level = 'Medium'
            elif score >= 0.1:
                severity_level = 'Low'
            else:
                severity_level = 'None'
            
            cve_data['severity_level'] = severity_level
    
    def generate_report(self, cve_data: Dict) -> Optional[str]:
        """生成CVE报告
        
        Args:
            cve_data: CVE信息
            
        Returns:
            Optional[str]: 报告文件路径
        """
        try:
            cve_id = cve_data.get('id', 'unknown')
            
            # 生成报告文件名
            report_filename = f"{cve_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            report_path = os.path.join(self.report_dir, report_filename)
            
            # 生成Markdown内容
            markdown_content = self._generate_markdown_content(cve_data)
            
            # 写入文件
            file_helper.write_file(report_path, markdown_content)
            
            logger.info(f"已生成CVE报告: {report_path}")
            return report_path
        except Exception as e:
            logger.error(f"生成CVE报告失败: {str(e)}")
            return None
    
    def _generate_markdown_content(self, cve_data: Dict) -> str:
        """生成Markdown格式的报告内容
        
        Args:
            cve_data: CVE信息
            
        Returns:
            str: Markdown内容
        """
        cve_id = cve_data.get('id', 'unknown')
        
        # 构建报告内容
        content = []
        content.append(f"# {cve_id}")
        content.append("")
        
        # 基本信息表格
        content.append("## 基本信息")
        content.append("| 属性 | 值 |")
        content.append("|------|-----|")
        
        # 添加严重性和CVSS评分
        if 'severity_level' in cve_data and cve_data['severity_level']:
            severity = cve_data['severity_level']
            # 根据严重性添加颜色标签
            if severity == 'Critical':
                severity_tag = '🔴 Critical'
            elif severity == 'High':
                severity_tag = '🟠 High'
            elif severity == 'Medium':
                severity_tag = '🟡 Medium'
            elif severity == 'Low':
                severity_tag = '🟢 Low'
            else:
                severity_tag = severity
            
            content.append(f"### 严重性: {severity_tag}")
            content.append("")
        
        if 'cvss_score' in cve_data and cve_data['cvss_score']:
            content.append(f"### CVSS评分: {cve_data['cvss_score']}")
            content.append("")
        
        # 描述
        content.append("## 漏洞描述")
        description = cve_data.get('description', '暂无描述')
        content.append(description)
        content.append("")
        
        # 翻译后的描述
        if 'translated_description' in cve_data and cve_data['translated_description']:
            content.append("## 中文描述")
            content.append(cve_data['translated_description'])
            content.append("")
        
        # 标签
        if 'tags' in cve_data and cve_data['tags']:
            content.append("## 标签")
            tags_str = ', '.join([f'`{tag}`' for tag in cve_data['tags']])
            content.append(tags_str)
            content.append("")
        
        # 参考链接
        if 'references' in cve_data and cve_data['references']:
            content.append("## 参考链接")
            for ref in cve_data['references']:
                if isinstance(ref, dict) and 'url' in ref:
                    url = ref['url']
                    source = ref.get('source', '').strip()
                    if source:
                        content.append(f"- [{source}]({url})")
                    else:
                        content.append(f"- [{url}]({url})")
                elif isinstance(ref, str):
                    content.append(f"- [{ref}]({ref})")
            content.append("")
        
        # POC信息
        if 'poc_info' in cve_data and cve_data['poc_info']:
            content.append("## POC信息")
            poc_info = cve_data['poc_info']
            
            if 'source' in poc_info:
                content.append(f"- **来源**: {poc_info['source']}")
            if 'url' in poc_info:
                content.append(f"- **链接**: [{poc_info['url']}]({poc_info['url']})")
            if 'description' in poc_info:
                content.append(f"- **描述**: {poc_info['description']}")
            if 'type' in poc_info:
                content.append(f"- **类型**: {poc_info['type']}")
            
            content.append("")
        
        # 日期信息
        content.append("## 日期信息")
        if 'published_date' in cve_data and cve_data['published_date']:
            content.append(f"- **发布日期**: {cve_data['published_date']}")
        if 'last_modified_date' in cve_data and cve_data['last_modified_date']:
            content.append(f"- **最后修改日期**: {cve_data['last_modified_date']}")
        content.append("")
        
        # 报告生成时间
        content.append(f"---\n报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return '\n'.join(content)
    
    def send_notification(self, cve_data: Dict) -> bool:
        """发送CVE通知
        
        Args:
            cve_data: CVE信息
            
        Returns:
            bool: 是否发送成功
        """
        try:
            cve_id = cve_data.get('id', 'unknown')
            
            # 构建通知标题
            severity = cve_data.get('severity_level', 'Unknown')
            title = f"[CVE监控] 发现新漏洞: {cve_id} ({severity})"
            
            # 构建通知内容
            content_parts = []
            content_parts.append(f"漏洞ID: {cve_id}")
            
            if 'severity_level' in cve_data:
                content_parts.append(f"严重性: {cve_data['severity_level']}")
            
            if 'cvss_score' in cve_data and cve_data['cvss_score']:
                content_parts.append(f"CVSS评分: {cve_data['cvss_score']}")
            
            # 使用简短描述
            description = cve_data.get('description', '暂无描述')
            # 如果有翻译后的描述，优先使用
            if 'translated_description' in cve_data and cve_data['translated_description']:
                description = cve_data['translated_description']
            
            # 限制描述长度
            if len(description) > 200:
                description = description[:200] + '...'
            content_parts.append(f"描述: {description}")
            
            # 添加报告路径（如果有）
            if 'report_path' in cve_data:
                content_parts.append(f"报告路径: {cve_data['report_path']}")
            
            # 构建完整内容
            content = '\n'.join(content_parts)
            
            # 发送通知
            results = notification_manager.send_all(title, content)
            
            # 检查是否有至少一个通知发送成功
            success_count = sum(1 for result in results.values() if result)
            
            if success_count > 0:
                logger.info(f"成功发送CVE通知: {cve_id}")
                return True
            else:
                logger.warning(f"所有通知渠道发送失败: {cve_id}")
                return False
        except Exception as e:
            logger.error(f"发送CVE通知时发生错误: {str(e)}")
            return False
    
    def process_batch_cves(self, cve_list: List[Dict]) -> List[Dict]:
        """批量处理CVE列表
        
        Args:
            cve_list: CVE信息列表
            
        Returns:
            List[Dict]: 处理后的CVE信息列表
        """
        processed_cves = []
        
        logger.info(f"开始批量处理 {len(cve_list)} 个CVE")
        
        for cve_data in cve_list:
            processed = self.process_cve(cve_data)
            processed_cves.append(processed)
        
        logger.info(f"完成批量处理，共处理 {len(processed_cves)} 个CVE")
        return processed_cves

# 创建默认实例
cve_processor = CVEProcessor()