import logging
import re
from typing import Dict, List, Optional

# 配置日志
logger = logging.getLogger('CVE_PushService.cve_processor')


class CVEProcessor:
    """CVE处理器，用于处理和增强CVE信息"""
    
    def __init__(self):
        # 初始化CVE处理器
        self.patterns = {
            'critical': [r'远程命令执行', r'RCE', r'任意代码执行', r'代码注入', r'缓冲区溢出'],
            'high': [r'SQL注入', r'XSS', r'跨站脚本', r'未授权访问', r'权限提升', r'信息泄露'],
            'medium': [r'拒绝服务', r'DoS', r'CSRF', r'跨站请求伪造', r'会话固定'],
            'low': [r'目录遍历', r'文件包含', r'弱密码', r'安全配置错误', r'输入验证不足']
        }
        
    def process_cve(self, cve_data: Dict) -> Dict:
        """处理CVE信息，添加额外的元数据和分析结果
        
        Args:
            cve_data: CVE数据字典
            
        Returns:
            Dict: 处理后的CVE数据
        """
        try:
            # 确保返回的是一个新的字典，避免修改原始数据
            processed_data = cve_data.copy()
            
            # 提取关键词和标签
            tags = self._extract_tags(processed_data.get('description', ''))
            processed_data['tags'] = tags
            
            # 根据描述和评分确定漏洞类型
            vuln_type = self._determine_vuln_type(processed_data)
            processed_data['vuln_type'] = vuln_type
            
            # 计算风险等级（如果未提供）
            if not processed_data.get('severity') or processed_data.get('severity') == 'UNKNOWN':
                severity = self._calculate_severity(processed_data)
                processed_data['severity'] = severity
                
            # 提取影响的软件和组件
            affected_products = self._extract_affected_products(processed_data.get('description', ''))
            if affected_products:
                processed_data['affected_products'] = affected_products
                
            # 添加处理时间戳
            from datetime import datetime
            processed_data['processed_at'] = datetime.now().isoformat()
            
            return processed_data
            
        except Exception as e:
            logger.error(f"处理CVE数据失败: {str(e)}")
            # 如果处理失败，返回原始数据
            return cve_data
    
    def _extract_tags(self, description: str) -> List[str]:
        """从描述中提取关键词作为标签"""
        tags = []
        if not description:
            return tags
        
        # 遍历预定义的模式
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    if category not in tags:
                        tags.append(category)
        
        # 添加常见的漏洞相关标签
        common_tags = ['CVE', '漏洞', '安全', '威胁']
        tags.extend([tag for tag in common_tags if tag not in tags])
        
        return tags
    
    def _determine_vuln_type(self, cve_data: Dict) -> str:
        """根据CVSS评分和描述确定漏洞类型"""
        description = cve_data.get('description', '')
        cvss_score = cve_data.get('cvss_score', 0.0)
        
        # 优先根据描述判断
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, description, re.IGNORECASE):
                    return pattern_type
        
        # 根据CVSS评分判断
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0:
            return 'low'
        else:
            return 'unknown'
    
    def _calculate_severity(self, cve_data: Dict) -> str:
        """根据CVSS评分计算严重性级别"""
        cvss_score = cve_data.get('cvss_score', 0.0)
        
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def _extract_affected_products(self, description: str) -> List[str]:
        """从描述中提取可能受影响的产品"""
        if not description:
            return []
        
        # 简单的产品提取逻辑，实际应用中可能需要更复杂的正则表达式
        product_patterns = [
            r'Windows', r'Linux', r'Android', r'iOS', r'MacOS',
            r'Chrome', r'Firefox', r'Safari', r'Edge',
            r'Apache', r'Nginx', r'IIS',
            r'MySQL', r'PostgreSQL', r'SQLite', r'MongoDB',
            r'Java', r'Python', r'PHP', r'Node\.js', r'Ruby'
        ]
        
        affected_products = []
        for pattern in product_patterns:
            if re.search(pattern, description, re.IGNORECASE):
                affected_products.append(pattern)
        
        return affected_products


# 创建默认实例
cve_processor = CVEProcessor()

# 导出主要方法供其他模块使用
def process_cve(cve_data: Dict) -> Dict:
    """处理CVE信息的便捷函数"""
    return cve_processor.process_cve(cve_data)