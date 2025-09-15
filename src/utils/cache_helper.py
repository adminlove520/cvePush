import os
import logging
import time
import hashlib
import requests
import os
from datetime import datetime, UTC

from src.config import settings

logger = logging.getLogger(__name__)

class CacheHelper:
    """缓存管理辅助类"""
    
    @staticmethod
    def get_cache_filename(url):
        """根据URL生成缓存文件名"""
        # 生成URL的哈希值
        url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
        
        # 获取缓存目录
        cache_dir = settings.get('CACHE.dir', os.path.join('data', 'cache'))
        return os.path.join(cache_dir, f"{url_hash}.json")
    
    @staticmethod
    def is_cache_valid(cache_file, cache_timeout):
        """检查缓存是否有效（未过期）"""
        try:
            # 检查缓存文件是否存在
            if not os.path.exists(cache_file):
                return False
            
            # 获取缓存文件的修改时间
            cache_time = os.path.getmtime(cache_file)
            # 计算当前时间与缓存时间的差值
            current_time = time.time()
            time_diff = current_time - cache_time
            
            # 判断缓存是否过期
            return time_diff < cache_timeout
        except Exception as e:
            logger.error(f"检查缓存有效性失败: {str(e)}")
            return False
    
    @staticmethod
    def fetch_json_with_cache(url, config=None):
        """获取JSON数据，支持缓存"""
        # 默认配置
        default_config = {
            'cache': {
                'enabled': True,
                'cache_dir': '.cache',
                'cache_timeout': 3600  # 默认1小时
            }
        }
        
        # 合并配置
        if config is None:
            config = default_config
        else:
            # 确保配置结构完整
            if 'cache' not in config:
                config['cache'] = default_config['cache']
            else:
                for key, value in default_config['cache'].items():
                    if key not in config['cache']:
                        config['cache'][key] = value
        
        # 如果缓存禁用，则直接获取数据
        if not config['cache']['enabled']:
            logger.info(f"缓存禁用，直接获取URL数据: {url}")
            return CacheHelper._fetch_url_data(url)
        
        # 构建缓存目录和文件路径
        cache_dir = config['cache']['cache_dir']
        cache_file = os.path.join(cache_dir, CacheHelper.get_cache_filename(url))
        cache_timeout = config['cache']['cache_timeout']
        
        # 检查缓存是否有效
        if CacheHelper.is_cache_valid(cache_file, cache_timeout):
            logger.info(f"使用缓存数据: {cache_file}")
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    import json
                    return json.load(f)
            except Exception as e:
                logger.error(f"读取缓存文件失败: {str(e)}")
        
        # 缓存无效或读取失败，重新获取数据
        logger.info(f"缓存无效或不存在，重新获取URL数据: {url}")
        data = CacheHelper._fetch_url_data(url)
        
        # 如果获取成功，保存到缓存
        if data is not None:
            try:
                # 确保缓存目录存在
                if not os.path.exists(cache_dir):
                    os.makedirs(cache_dir)
                
                with open(cache_file, 'w', encoding='utf-8') as f:
                    import json
                    json.dump(data, f, ensure_ascii=False)
                logger.info(f"数据已缓存到: {cache_file}")
            except Exception as e:
                logger.warning(f"保存缓存文件失败: {str(e)}")
        
        return data
    
    @staticmethod
    def _fetch_url_data(url):
        """从URL获取数据的内部方法"""
        try:
            logger.debug(f"正在请求URL: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()  # 检查请求是否成功
            
            # 尝试解析JSON
            data = response.json()
            logger.debug(f"成功获取并解析URL数据")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"请求URL失败: {str(e)}")
        except ValueError as e:
            logger.error(f"解析JSON数据失败: {str(e)}")
        except Exception as e:
            logger.error(f"获取URL数据时发生未知错误: {str(e)}")
        
        return None
    
    @staticmethod
    def clear_cache(cache_dir='.cache', older_than=None):
        """清理缓存文件，可选只清理指定时间之前的缓存"""
        try:
            if not os.path.exists(cache_dir):
                logger.info(f"缓存目录不存在: {cache_dir}")
                return
            
            current_time = time.time()
            deleted_count = 0
            
            for filename in os.listdir(cache_dir):
                file_path = os.path.join(cache_dir, filename)
                if os.path.isfile(file_path):
                    # 如果指定了时间条件，检查文件是否过期
                    if older_than is not None:
                        file_time = os.path.getmtime(file_path)
                        if current_time - file_time > older_than:
                            os.remove(file_path)
                            deleted_count += 1
                    else:
                        # 否则直接删除所有缓存文件
                        os.remove(file_path)
                        deleted_count += 1
            
            logger.info(f"已清理 {deleted_count} 个缓存文件")
        except Exception as e:
            logger.error(f"清理缓存失败: {str(e)}")
    
    @staticmethod
    def get_cache_info(cache_dir='.cache'):
        """获取缓存信息"""
        try:
            if not os.path.exists(cache_dir):
                return {'exists': False, 'file_count': 0, 'total_size': 0}
            
            file_count = 0
            total_size = 0
            
            for filename in os.listdir(cache_dir):
                file_path = os.path.join(cache_dir, filename)
                if os.path.isfile(file_path):
                    file_count += 1
                    total_size += os.path.getsize(file_path)
            
            return {
                'exists': True,
                'file_count': file_count,
                'total_size': total_size,
                'human_size': CacheHelper._format_size(total_size)
            }
        except Exception as e:
            logger.error(f"获取缓存信息失败: {str(e)}")
            return {'exists': False, 'file_count': 0, 'total_size': 0}
    
    @staticmethod
    def _format_size(size_bytes):
        """格式化文件大小为人类可读的形式"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    @staticmethod
    def get_cached_data(cache_key):
        """根据缓存键获取缓存数据"""
        try:
            # 使用默认缓存目录
            cache_dir = settings.get('CACHE.cache_dir', '.cache')
            cache_file = os.path.join(cache_dir, f"{cache_key}.json")
            cache_timeout = settings.get('CACHE.cache_timeout', 3600)
            
            # 检查缓存是否有效
            if CacheHelper.is_cache_valid(cache_file, cache_timeout):
                logger.debug(f"从缓存获取数据: {cache_file}")
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        import json
                        return json.load(f)
                except Exception as e:
                    logger.error(f"读取缓存文件失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取缓存数据失败: {str(e)}")
            return None

    @staticmethod
    def cache_data(cache_key, data):
        """将数据缓存到文件"""
        try:
            # 使用默认缓存目录
            cache_dir = settings.get('CACHE.dir', os.path.join('data', 'cache'))
            cache_file = os.path.join(cache_dir, f"{cache_key}.json")
            
            # 确保缓存目录存在
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
            
            # 写入缓存文件
            with open(cache_file, 'w', encoding='utf-8') as f:
                import json
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.debug(f"数据已缓存到: {cache_file}")
            return True
        except Exception as e:
            logger.error(f"缓存数据失败: {str(e)}")
            return False

# 创建默认实例
cache_helper = CacheHelper()