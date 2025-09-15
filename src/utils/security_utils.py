import os
import logging
import time
import hmac
import hashlib
import base64
import urllib.parse
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

class SecurityUtils:
    """安全相关工具类"""
    
    @staticmethod
    def generate_signature(data, secret_key, timestamp=None):
        """生成基于HMAC-SHA256的签名
        
        Args:
            data: 要签名的数据（可以是字符串或字典）
            secret_key: 密钥
            timestamp: 时间戳，如果为None则使用当前时间
            
        Returns:
            tuple: (签名字符串, 时间戳)
        """
        try:
            # 如果没有提供时间戳，使用当前时间
            if timestamp is None:
                timestamp = str(int(time.time() * 1000))  # 毫秒时间戳
            
            # 如果数据是字典，转换为URL编码的字符串
            if isinstance(data, dict):
                data_str = urllib.parse.urlencode(data)
            else:
                data_str = str(data)
            
            # 构建签名字符串
            sign_str = f"{timestamp}\n{data_str}"
            
            # 使用HMAC-SHA256算法生成签名
            hmac_code = hmac.new(
                secret_key.encode('utf-8'),
                sign_str.encode('utf-8'),
                digestmod=hashlib.sha256
            ).digest()
            
            # 使用Base64编码
            signature = base64.b64encode(hmac_code).decode('utf-8')
            
            logger.debug(f"签名生成成功，时间戳: {timestamp}")
            return signature, timestamp
        except Exception as e:
            logger.error(f"生成签名失败: {str(e)}")
            return None, timestamp
    
    @staticmethod
    def verify_signature(data, signature, secret_key, timestamp, max_time_diff=300):
        """验证签名
        
        Args:
            data: 要验证的数据
            signature: 待验证的签名
            secret_key: 密钥
            timestamp: 时间戳
            max_time_diff: 最大允许的时间差（秒），默认5分钟
            
        Returns:
            bool: 签名是否有效
        """
        try:
            # 验证时间戳是否在允许的时间范围内
            current_time = int(time.time())
            given_time = int(timestamp) // 1000  # 转换为秒
            
            if abs(current_time - given_time) > max_time_diff:
                logger.warning(f"签名时间戳过期，当前时间: {current_time}，签名时间: {given_time}")
                return False
            
            # 重新生成签名进行比较
            generated_signature, _ = SecurityUtils.generate_signature(data, secret_key, timestamp)
            
            if generated_signature is None:
                logger.error("生成验证签名失败")
                return False
            
            # 比较签名（使用安全的比较方法防止计时攻击）
            is_valid = hmac.compare_digest(generated_signature, signature)
            
            if not is_valid:
                logger.warning("签名验证失败，签名不匹配")
            else:
                logger.debug("签名验证成功")
            
            return is_valid
        except Exception as e:
            logger.error(f"验证签名时发生错误: {str(e)}")
            return False
    
    @staticmethod
    def get_dingtalk_signature(secret_key):
        """生成钉钉机器人的签名
        
        Args:
            secret_key: 钉钉机器人的密钥
            
        Returns:
            tuple: (签名字符串, 时间戳)
        """
        try:
            timestamp = str(int(time.time() * 1000))
            
            # 构建签名字符串
            string_to_sign = f"{timestamp}\n{secret_key}"
            
            # 使用HMAC-SHA256算法生成签名
            hmac_code = hmac.new(
                secret_key.encode('utf-8'),
                string_to_sign.encode('utf-8'),
                digestmod=hashlib.sha256
            ).digest()
            
            # 对签名进行Base64编码，然后进行URL编码
            signature = urllib.parse.quote_plus(base64.b64encode(hmac_code))
            
            logger.debug(f"钉钉签名生成成功，时间戳: {timestamp}")
            return signature, timestamp
        except Exception as e:
            logger.error(f"生成钉钉签名失败: {str(e)}")
            return None, timestamp
    
    @staticmethod
    def secure_compare(a, b):
        """安全地比较两个字符串，防止计时攻击
        
        Args:
            a: 第一个字符串
            b: 第二个字符串
            
        Returns:
            bool: 两个字符串是否相等
        """
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def hash_data(data, algorithm='sha256'):
        """计算数据的哈希值
        
        Args:
            data: 要哈希的数据
            algorithm: 哈希算法，默认为'sha256'
            
        Returns:
            str: 哈希值的十六进制字符串
        """
        try:
            # 选择哈希算法
            if algorithm.lower() == 'md5':
                hash_obj = hashlib.md5()
            elif algorithm.lower() == 'sha1':
                hash_obj = hashlib.sha1()
            elif algorithm.lower() == 'sha256':
                hash_obj = hashlib.sha256()
            elif algorithm.lower() == 'sha512':
                hash_obj = hashlib.sha512()
            else:
                logger.error(f"不支持的哈希算法: {algorithm}")
                return None
            
            # 处理数据
            if isinstance(data, bytes):
                hash_obj.update(data)
            else:
                hash_obj.update(str(data).encode('utf-8'))
            
            # 返回十六进制字符串
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"计算哈希值失败: {str(e)}")
            return None
    
    @staticmethod
    def generate_nonce(length=16):
        """生成随机的nonce值
        
        Args:
            length: nonce值的长度
            
        Returns:
            str: 随机的nonce值
        """
        try:
            # 使用os.urandom生成加密安全的随机字节
            random_bytes = os.urandom(length)
            # 转换为十六进制字符串
            nonce = random_bytes.hex()
            # 截取指定长度
            return nonce[:length]
        except Exception as e:
            logger.error(f"生成nonce失败: {str(e)}")
            # 降级方案：使用时间戳和随机数
            import random
            return f"{int(time.time() * 1000)}{random.randint(1000, 9999)}"
    
    @staticmethod
    def validate_json_signature(request_json, secret_key, signature_field='signature', timestamp_field='timestamp'):
        """验证JSON请求中的签名
        
        Args:
            request_json: 请求的JSON数据
            secret_key: 密钥
            signature_field: 签名字段名
            timestamp_field: 时间戳字段名
            
        Returns:
            bool: 签名是否有效
        """
        try:
            # 检查必要的字段是否存在
            if not isinstance(request_json, dict):
                logger.warning("请求数据不是有效的JSON对象")
                return False
            
            if signature_field not in request_json:
                logger.warning(f"请求中缺少{signature_field}字段")
                return False
            
            if timestamp_field not in request_json:
                logger.warning(f"请求中缺少{timestamp_field}字段")
                return False
            
            # 提取签名和时间戳
            signature = request_json[signature_field]
            timestamp = request_json[timestamp_field]
            
            # 创建不包含签名字段的数据副本
            data_without_signature = request_json.copy()
            del data_without_signature[signature_field]
            
            # 验证签名
            return SecurityUtils.verify_signature(data_without_signature, signature, secret_key, timestamp)
        except Exception as e:
            logger.error(f"验证JSON签名时发生错误: {str(e)}")
            return False

# 创建默认实例
security_utils = SecurityUtils()