# 配置模块

"""
配置模块负责管理应用程序的设置和日志配置。
"""

# 导出配置组件
from .settings import Settings
from .logging_config import setup_logging

# 创建默认实例
settings = Settings()

__all__ = [
    'Settings',
    'setup_logging',
    'settings'
]