import os
import json
import yaml
import logging
from typing import Dict, Optional, Any
import copy

logger = logging.getLogger(__name__)

class Settings:
    """配置管理类"""
    
    # 默认配置
    DEFAULT_SETTINGS = {
        # 数据库配置
        'DATABASE': {
            'path': 'data/cve_data.db',
            'timeout': 30,
            'check_same_thread': False
        },
        
        # 缓存配置
        'CACHE': {
            'enabled': True,
            'dir': 'data/cache',
            'ttl': 3600,  # 缓存有效期（秒）
            'max_size': 100 * 1024 * 1024  # 最大缓存大小（100MB）
        },
        
        # 日志配置
        'LOGGING': {
            'level': 'INFO',
            'file': 'logs/cve_push_service.log',
            'format': '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            'max_bytes': 10 * 1024 * 1024,  # 10MB
            'backup_count': 5,
            'enable_console': True,
            'enable_file': True
        },
        
        # POC监控配置
        'POC_MONITOR': {
            'enabled': True,
            'sources': [
                'nvd', 'github', 'exploit_db', 'cve_detail'
            ],
            'check_interval': 3600,  # 检查间隔（秒）
            'new_vulns_flag': 'data/new_vulns.flag',
            'report_dir': 'data/reports',
            'max_retries': 3,
            'retry_interval': 5  # 重试间隔（秒）
        },
        
        # 翻译配置
        'TRANSLATION': {
            'enabled': True,
            'default_language': 'zh',
            'timeout': 10,
            'providers': ['youdao', 'google'],
            'youdao': {
                'app_id': '',
                'app_secret': ''
            },
            'google': {
                'api_key': '',
                'max_length': 5000
            }
        },
        
        # API配置
        'API': {
            'nvd': {
                'base_url': 'https://services.nvd.nist.gov/rest/json/cves/1.0/',
                'api_key': '',
                'rate_limit': 5  # 每秒请求数
            },
            'github': {
                'base_url': 'https://api.github.com/',
                'token': '',
                'rate_limit': 30  # 每分钟请求数
            },
            'exploit_db': {
                'base_url': 'https://www.exploit-db.com/'
            }
        },
        
        # 通知配置
        'NOTIFICATION': {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.example.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'sender': 'cve-alert@example.com',
                'recipients': []
            },
            'dingtalk': {
                'enabled': False,
                'webhook_url': '',
                'secret_key': ''
            },
            'wechat_work': {
                'enabled': False,
                'webhook_url': ''
            },
            'webhook': {
                'enabled': False,
                'url': '',
                'headers': {},
                'method': 'POST'
            }
        },
        
        # 安全配置
        'SECURITY': {
            'secret_key': 'change_me_to_a_secure_key',
            'enable_signature': True,
            'signature_ttl': 300  # 签名有效期（秒）
        },
        
        # 应用配置
        'APP': {
            'name': 'CVE_PushService',
            'version': '1.0.0',
            'debug': False,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """初始化配置管理器
        
        Args:
            config_file: 配置文件路径
        """
        # 初始化配置为默认配置的深拷贝
        self._settings = copy.deepcopy(self.DEFAULT_SETTINGS)
        
        # 加载配置文件
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        else:
            # 尝试加载默认配置文件
            default_config_files = [
                'config.yaml',
                'config.yml',
                'config.json',
                'settings.yaml',
                'settings.yml',
                'settings.json',
                'data/config.yaml',
                'data/config.json'
            ]
            
            for default_file in default_config_files:
                if os.path.exists(default_file):
                    self.load_from_file(default_file)
                    break
    
    def load_from_file(self, config_file: str) -> None:
        """从文件加载配置
        
        Args:
            config_file: 配置文件路径
        """
        try:
            file_ext = os.path.splitext(config_file)[1].lower()
            
            with open(config_file, 'r', encoding='utf-8') as f:
                if file_ext in ['.yaml', '.yml']:
                    user_config = yaml.safe_load(f)
                elif file_ext == '.json':
                    user_config = json.load(f)
                else:
                    logger.error(f"不支持的配置文件格式: {file_ext}")
                    return
            
            if user_config:
                # 统一配置键的大小写
                normalized_config = self._normalize_config_keys(user_config)
                # 合并配置
                self._merge_config(self._settings, normalized_config)
                logger.info(f"成功从配置文件加载配置: {config_file}")
        except Exception as e:
            logger.error(f"加载配置文件失败: {str(e)}")
            
    def _normalize_config_keys(self, config: Dict) -> Dict:
        """标准化配置键的大小写"""
        normalized = {}
        for key, value in config.items():
            # 对于顶层键，转换为大写（如果需要）
            normalized_key = key.upper() if key.lower() in ['cache', 'logging'] else key
            if isinstance(value, dict):
                normalized[normalized_key] = self._normalize_config_keys(value)
            else:
                normalized[normalized_key] = value
        return normalized
    
    def _merge_config(self, base: Dict, update: Dict) -> None:
        """递归合并配置字典
        
        Args:
            base: 基础配置字典
            update: 要合并的配置字典
        """
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                # 如果都是字典，递归合并
                self._merge_config(base[key], value)
            else:
                # 否则直接替换
                base[key] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """获取配置值
        
        Args:
            key_path: 配置键路径，使用点表示法，如 'DATABASE.path'
            default: 默认值
            
        Returns:
            Any: 配置值或默认值
        """
        keys = key_path.split('.')
        value = self._settings
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """设置配置值
        
        Args:
            key_path: 配置键路径
            value: 配置值
        """
        keys = key_path.split('.')
        config = self._settings
        
        # 遍历除最后一个键以外的所有键
        for key in keys[:-1]:
            if key not in config or not isinstance(config[key], dict):
                config[key] = {}
            config = config[key]
        
        # 设置最后一个键的值
        config[keys[-1]] = value
        logger.debug(f"已设置配置: {key_path} = {value}")
    
    def save_to_file(self, config_file: str) -> bool:
        """保存配置到文件
        
        Args:
            config_file: 配置文件路径
            
        Returns:
            bool: 是否保存成功
        """
        try:
            # 确保目录存在
            dir_path = os.path.dirname(config_file)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path)
            
            file_ext = os.path.splitext(config_file)[1].lower()
            
            with open(config_file, 'w', encoding='utf-8') as f:
                if file_ext in ['.yaml', '.yml']:
                    yaml.dump(self._settings, f, allow_unicode=True, default_flow_style=False)
                elif file_ext == '.json':
                    json.dump(self._settings, f, ensure_ascii=False, indent=2)
                else:
                    logger.error(f"不支持的配置文件格式: {file_ext}")
                    return False
            
            logger.info(f"成功保存配置到文件: {config_file}")
            return True
        except Exception as e:
            logger.error(f"保存配置文件失败: {str(e)}")
            return False
    
    def get_all(self) -> Dict[str, Any]:
        """获取所有配置
        
        Returns:
            Dict[str, Any]: 所有配置的字典
        """
        return copy.deepcopy(self._settings)
    
    def validate(self) -> bool:
        """验证配置有效性
        
        Returns:
            bool: 配置是否有效
        """
        try:
            # 检查必要的配置项
            required_configs = [
                ('DATABASE.path', str),
                ('CACHE.dir', str),
                ('LOGGING.level', str),
                ('POC_MONITOR.new_vulns_flag', str),
                ('POC_MONITOR.report_dir', str),
                ('SECURITY.secret_key', str)
            ]
            
            for key_path, expected_type in required_configs:
                value = self.get(key_path)
                if value is None:
                    logger.error(f"配置项缺失: {key_path}")
                    return False
                if not isinstance(value, expected_type):
                    logger.error(f"配置项类型错误: {key_path} 应为 {expected_type.__name__}")
                    return False
            
            # 检查目录是否存在，不存在则创建
            dirs_to_check = [
                os.path.dirname(self.get('DATABASE.path')),
                self.get('CACHE.dir'),
                os.path.dirname(self.get('LOGGING.file')),
                os.path.dirname(self.get('POC_MONITOR.new_vulns_flag')),
                self.get('POC_MONITOR.report_dir')
            ]
            
            for dir_path in dirs_to_check:
                if dir_path and not os.path.exists(dir_path):
                    try:
                        os.makedirs(dir_path)
                        logger.info(f"已创建目录: {dir_path}")
                    except Exception as e:
                        logger.error(f"创建目录失败: {dir_path}, 错误: {str(e)}")
                        return False
            
            logger.info("配置验证通过")
            return True
        except Exception as e:
            logger.error(f"配置验证失败: {str(e)}")
            return False
    
    def __getitem__(self, key_path: str) -> Any:
        """支持字典风格的获取配置"""
        return self.get(key_path)
    
    def __setitem__(self, key_path: str, value: Any) -> None:
        """支持字典风格的设置配置"""
        self.set(key_path, value)

# 创建默认实例
def get_default_settings(config_file: Optional[str] = None) -> Settings:
    """获取默认配置实例
    
    Args:
        config_file: 配置文件路径
        
    Returns:
        Settings: 配置实例
    """
    return Settings(config_file)

# 全局配置实例
settings = get_default_settings()