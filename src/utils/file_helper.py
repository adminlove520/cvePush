import os
import logging
import json
import yaml

logger = logging.getLogger(__name__)

class FileHelper:
    """文件操作辅助类"""
    
    @staticmethod
    def ensure_directory_exists(dir_path):
        """确保目录存在，如果不存在则创建"""
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                logger.info(f"创建目录: {dir_path}")
            return True
        except Exception as e:
            logger.error(f"创建目录失败: {dir_path}, 错误: {str(e)}")
            return False
    
    @staticmethod
    def read_file(file_path, encoding='utf-8'):
        """读取文件内容"""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"文件不存在: {file_path}")
                return None
            
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            return content
        except Exception as e:
            logger.error(f"读取文件失败: {file_path}, 错误: {str(e)}")
            return None
    
    @staticmethod
    def write_file(file_path, content, encoding='utf-8'):
        """写入文件内容"""
        try:
            # 确保父目录存在
            dir_path = os.path.dirname(file_path)
            if dir_path and not os.path.exists(dir_path):
                FileHelper.ensure_directory_exists(dir_path)
            
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            logger.info(f"文件已保存: {file_path}")
            return True
        except Exception as e:
            logger.error(f"写入文件失败: {file_path}, 错误: {str(e)}")
            return False
    
    @staticmethod
    def append_file(file_path, content, encoding='utf-8'):
        """追加内容到文件"""
        try:
            # 确保父目录存在
            dir_path = os.path.dirname(file_path)
            if dir_path and not os.path.exists(dir_path):
                FileHelper.ensure_directory_exists(dir_path)
            
            with open(file_path, 'a', encoding=encoding) as f:
                f.write(content)
            logger.info(f"内容已追加到文件: {file_path}")
            return True
        except Exception as e:
            logger.error(f"追加内容到文件失败: {file_path}, 错误: {str(e)}")
            return False
    
    @staticmethod
    def read_json(file_path, encoding='utf-8'):
        """读取JSON文件"""
        content = FileHelper.read_file(file_path, encoding)
        if content:
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"解析JSON文件失败: {file_path}, 错误: {str(e)}")
        return None
    
    @staticmethod
    def write_json(file_path, data, encoding='utf-8', indent=2):
        """写入JSON文件"""
        try:
            content = json.dumps(data, ensure_ascii=False, indent=indent)
            return FileHelper.write_file(file_path, content, encoding)
        except Exception as e:
            logger.error(f"转换数据为JSON失败: {str(e)}")
            return False
    
    @staticmethod
    def read_yaml(file_path, encoding='utf-8'):
        """读取YAML文件"""
        content = FileHelper.read_file(file_path, encoding)
        if content:
            try:
                return yaml.safe_load(content)
            except yaml.YAMLError as e:
                logger.error(f"解析YAML文件失败: {file_path}, 错误: {str(e)}")
        return None
    
    @staticmethod
    def write_yaml(file_path, data, encoding='utf-8'):
        """写入YAML文件"""
        try:
            content = yaml.dump(data, allow_unicode=True, default_flow_style=False)
            return FileHelper.write_file(file_path, content, encoding)
        except Exception as e:
            logger.error(f"转换数据为YAML失败: {str(e)}")
            return False
    
    @staticmethod
    def list_files(dir_path, extension=None):
        """列出目录中的文件，可选择按扩展名过滤"""
        try:
            if not os.path.exists(dir_path):
                logger.warning(f"目录不存在: {dir_path}")
                return []
            
            files = []
            for file in os.listdir(dir_path):
                file_path = os.path.join(dir_path, file)
                if os.path.isfile(file_path):
                    if extension is None or file.endswith(extension):
                        files.append(file_path)
            return files
        except Exception as e:
            logger.error(f"列出目录文件失败: {dir_path}, 错误: {str(e)}")
            return []
    
    @staticmethod
    def get_file_size(file_path):
        """获取文件大小（字节）"""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"文件不存在: {file_path}")
                return 0
            return os.path.getsize(file_path)
        except Exception as e:
            logger.error(f"获取文件大小失败: {file_path}, 错误: {str(e)}")
            return 0
    
    @staticmethod
    def delete_file(file_path):
        """删除文件"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"文件已删除: {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"删除文件失败: {file_path}, 错误: {str(e)}")
            return False

# 创建默认实例
file_helper = FileHelper()