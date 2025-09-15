import os
from datetime import timedelta


class Settings:
    """系统配置类"""
    
    # 项目根目录
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 数据库配置
    DB_PATH = os.path.join(BASE_DIR, 'data', 'cve_data.db')
    DB_TIMEOUT = 30  # 数据库连接超时时间（秒）
    
    # 缓存配置
    CACHE_DIR = os.path.join(BASE_DIR, 'data', 'cache')
    CACHE_EXPIRE_TIME = timedelta(hours=24)  # 缓存过期时间
    CACHE_MAX_SIZE = 500  # 最大缓存文件数量
    
    # NVD API配置
    NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    NVD_API_RATE_LIMIT = 5  # 每分钟请求次数限制
    NVD_API_RETRY_COUNT = 3  # API请求失败重试次数
    NVD_API_RETRY_DELAY = 10  # 重试间隔（秒）
    
    # POC监控配置
    POC_MONITOR_CHECK_INTERVAL = 3600  # 检查间隔（秒）
    NEW_VULNS_FLAG_FILE = os.path.join(BASE_DIR, 'data', 'new_vulns.flag')
    
    # 日志配置
    LOG_LEVEL = 'INFO'  # 日志级别：DEBUG, INFO, WARNING, ERROR, CRITICAL
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = os.path.join(BASE_DIR, 'logs', 'cve_push_service.log')
    
    # API配置
    API_HOST = '0.0.0.0'
    API_PORT = 8000
    
    # 通知配置
    ENABLE_EMAIL_NOTIFICATIONS = False
    ENABLE_WECHAT_NOTIFICATIONS = False
    
    # 威胁情报评分阈值
    HIGH_RISK_THRESHOLD = 7.0  # CVSS高风险阈值
    CRITICAL_RISK_THRESHOLD = 9.0  # CVSS严重风险阈值
    
    # POC评分配置
    POC_SOURCE_WEIGHTS = {
        'github': 10,
        'exploit_db': 9,
        'seebug': 8,
        'packetstorm': 7,
        'wooyun': 6
    }


# 创建设置实例
settings = Settings()


# 兼容旧的配置导入
def get_setting(key, default=None):
    """获取配置项的便捷函数"""
    if hasattr(settings, key):
        return getattr(settings, key)
    return default