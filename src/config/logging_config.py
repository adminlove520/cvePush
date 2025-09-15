import logging
import os
from datetime import datetime
import sys
from typing import Dict, Optional, Union

class LoggingConfig:
    """日志配置类"""
    
    # 定义日志格式
    DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DETAILED_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
    JSON_LOG_FORMAT = '{"timestamp": "%(asctime)s", "logger": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}'
    
    # 定义日志级别映射
    LEVEL_MAP = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'WARN': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    
    @classmethod
    def setup_logging(cls,
                     log_level: Union[str, int] = 'INFO',
                     log_file: Optional[str] = None,
                     log_format: Optional[str] = None,
                     max_bytes: int = 10 * 1024 * 1024,  # 10MB
                     backup_count: int = 5,
                     enable_console: bool = True,
                     enable_file: bool = True,
                     json_format: bool = False) -> None:
        """设置全局日志配置
        
        Args:
            log_level: 日志级别，如'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'或对应的数字
            log_file: 日志文件路径，如果为None则不输出到文件
            log_format: 日志格式字符串
            max_bytes: 日志文件最大字节数，超过后会分割
            backup_count: 保留的备份日志文件数量
            enable_console: 是否启用控制台输出
            enable_file: 是否启用文件输出
            json_format: 是否使用JSON格式的日志
        """
        # 如果未提供日志格式，使用默认格式
        if log_format is None:
            if json_format:
                log_format = cls.JSON_LOG_FORMAT
            else:
                log_format = cls.DETAILED_LOG_FORMAT
        
        # 转换日志级别
        if isinstance(log_level, str):
            log_level = cls.LEVEL_MAP.get(log_level.upper(), logging.INFO)
        
        # 获取根日志记录器
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # 清除已有的处理器
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # 创建格式化器
        formatter = logging.Formatter(log_format)
        
        # 添加控制台处理器
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
        
        # 添加文件处理器
        if enable_file and log_file:
            # 确保日志目录存在
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # 创建轮转文件处理器
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        
        # 记录日志配置信息
        logger = logging.getLogger(__name__)
        logger.info(f"日志系统已初始化，级别: {logging.getLevelName(log_level)}")
        if enable_console:
            logger.info("控制台日志已启用")
        if enable_file and log_file:
            logger.info(f"文件日志已启用，路径: {log_file}")
    
    @classmethod
    def setup_daily_logging(cls,
                          log_level: Union[str, int] = 'INFO',
                          log_file: Optional[str] = None,
                          log_format: Optional[str] = None,
                          backup_count: int = 7,
                          enable_console: bool = True,
                          enable_file: bool = True,
                          json_format: bool = False) -> None:
        """设置基于日期的轮转日志
        
        Args:
            log_level: 日志级别
            log_file: 日志文件路径
            log_format: 日志格式字符串
            backup_count: 保留的备份日志文件数量
            enable_console: 是否启用控制台输出
            enable_file: 是否启用文件输出
            json_format: 是否使用JSON格式的日志
        """
        # 如果未提供日志格式，使用默认格式
        if log_format is None:
            if json_format:
                log_format = cls.JSON_LOG_FORMAT
            else:
                log_format = cls.DETAILED_LOG_FORMAT
        
        # 转换日志级别
        if isinstance(log_level, str):
            log_level = cls.LEVEL_MAP.get(log_level.upper(), logging.INFO)
        
        # 获取根日志记录器
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # 清除已有的处理器
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # 创建格式化器
        formatter = logging.Formatter(log_format)
        
        # 添加控制台处理器
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
        
        # 添加文件处理器
        if enable_file and log_file:
            # 确保日志目录存在
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # 创建按日期轮转的文件处理器
            from logging.handlers import TimedRotatingFileHandler
            file_handler = TimedRotatingFileHandler(
                log_file,
                when='midnight',  # 在午夜时分轮转
                interval=1,       # 每天轮转一次
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        
        # 记录日志配置信息
        logger = logging.getLogger(__name__)
        logger.info(f"日志系统已初始化，级别: {logging.getLevelName(log_level)}")
        if enable_console:
            logger.info("控制台日志已启用")
        if enable_file and log_file:
            logger.info(f"日期轮转日志已启用，路径: {log_file}")
    
    @classmethod
    def get_logger(cls, name: Optional[str] = None) -> logging.Logger:
        """获取指定名称的日志记录器
        
        Args:
            name: 日志记录器名称
            
        Returns:
            logging.Logger: 日志记录器实例
        """
        return logging.getLogger(name)
    
    @classmethod
    def set_module_level(cls, module_name: str, level: Union[str, int]) -> None:
        """设置指定模块的日志级别
        
        Args:
            module_name: 模块名称
            level: 日志级别
        """
        if isinstance(level, str):
            level = cls.LEVEL_MAP.get(level.upper(), logging.INFO)
        
        logger = logging.getLogger(module_name)
        logger.setLevel(level)
        
        # 记录日志级别设置
        logging.getLogger(__name__).info(f"已设置模块 {module_name} 的日志级别为 {logging.getLevelName(level)}")
    
    @classmethod
    def disable_external_loggers(cls, exclude: Optional[list] = None) -> None:
        """禁用外部库的日志输出
        
        Args:
            exclude: 要排除的模块列表（不禁用这些模块的日志）
        """
        exclude = exclude or []
        
        # 常见的外部库
        external_loggers = [
            'requests', 'urllib3', 'http.client', 'botocore', 'boto3',
            'paramiko', 'matplotlib', 'PIL', 'numpy', 'pandas'
        ]
        
        for logger_name in external_loggers:
            if logger_name not in exclude:
                logger = logging.getLogger(logger_name)
                logger.setLevel(logging.WARNING)
                # 关闭传播
                logger.propagate = False
        
        logging.getLogger(__name__).info(f"已禁用外部库日志输出，排除: {exclude}")
    
    @classmethod
    def create_log_dir(cls, base_dir: str) -> str:
        """创建日志目录，如果不存在
        
        Args:
            base_dir: 基础目录
            
        Returns:
            str: 日志目录路径
        """
        # 创建基于日期的日志子目录
        today = datetime.now().strftime('%Y-%m-%d')
        log_dir = os.path.join(base_dir, today)
        
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        return log_dir

# 默认的日志设置函数，保持向后兼容性
def setup_logging(
    log_level: Union[str, int] = 'INFO',
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    enable_console: bool = True,
    enable_file: bool = True
) -> None:
    """设置全局日志配置（保持向后兼容）
    
    Args:
        log_level: 日志级别
        log_file: 日志文件路径
        log_format: 日志格式字符串
        max_bytes: 日志文件最大字节数
        backup_count: 保留的备份日志文件数量
        enable_console: 是否启用控制台输出
        enable_file: 是否启用文件输出
    """
    LoggingConfig.setup_logging(
        log_level=log_level,
        log_file=log_file,
        log_format=log_format,
        max_bytes=max_bytes,
        backup_count=backup_count,
        enable_console=enable_console,
        enable_file=enable_file
    )