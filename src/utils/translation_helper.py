import requests
import time
import logging
import requests


class TranslationHelper:
    """翻译助手类，提供翻译功能"""
    
    def __init__(self):
        """初始化翻译助手"""
        # 配置翻译API参数
        self.timeout = 10  # 请求超时时间（秒）
        self.retry_count = 3  # 重试次数
        self.retry_interval = 2  # 重试间隔（秒）
    
    @staticmethod
    def translate(text: str, target_lang: str = 'zh') -> str:
        """翻译文本
        
        Args:
            text: 要翻译的文本
            target_lang: 目标语言，默认为中文
            
        Returns:
            str: 翻译后的文本，如果翻译失败则返回原始文本
        """
        if not text:
            return text
        
        # 先尝试有道翻译
        result = TranslationHelper._youdao_translate(text, target_lang)
        
        # 如果有道翻译失败，尝试Google翻译
        if not result:
            result = TranslationHelper._google_translate(text, target_lang)
        
        # 如果翻译都失败，返回原始文本
        return result if result else text
    
    @staticmethod
    def _youdao_translate(text: str, target_lang: str) -> str:
        """使用有道翻译API翻译文本
        
        Args:
            text: 要翻译的文本
            target_lang: 目标语言
            
        Returns:
            str: 翻译后的文本，如果翻译失败则返回None
        """
        try:
            helper = TranslationHelper()
            
            # 准备请求参数
            url = 'https://aidemo.youdao.com/trans'
            params = {
                'q': text,
                'from': 'auto',
                'to': target_lang
            }
            
            # 准备请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # 发送请求
            for attempt in range(helper.retry_count):
                try:
                    response = requests.post(
                        url,
                        data=params,
                        headers=headers,
                        timeout=helper.timeout
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        # 检查是否包含translation字段
                        if 'translation' in data and data['translation']:
                            return data['translation'][0]
                except Exception as e:
                    logging.warning(f"有道翻译请求异常: {str(e)}")
                
                # 重试前等待
                if attempt < helper.retry_count - 1:
                    time.sleep(helper.retry_interval)
        except Exception as e:
            logging.error(f"有道翻译时发生错误: {str(e)}")
        
        return None
    
    @staticmethod
    def detect_language(text: str) -> str:
        """检测文本语言
        
        Args:
            text: 要检测的文本
            
        Returns:
            str: 语言代码（如'en'、'zh'等），默认返回'en'
        """
        if not text:
            return 'en'
            
        # 简单的语言检测逻辑
        # 检查是否包含中文字符
        if any('\u4e00' <= char <= '\u9fff' for char in text):
            return 'zh'
        
        # 默认返回英文
        return 'en'
    
    @staticmethod
    def _google_translate(text: str, target_lang: str) -> str:
        """使用Google翻译API翻译文本
        
        Args:
            text: 要翻译的文本
            target_lang: 目标语言
            
        Returns:
            str: 翻译后的文本，如果翻译失败则返回None
        """
        try:
            helper = TranslationHelper()
            
            # 准备请求参数
            url = 'https://translate.googleapis.com/translate_a/single'
            params = {
                'client': 'gtx',
                'sl': 'auto',  # 源语言自动检测
                'tl': target_lang,  # 目标语言
                'dt': 't',
                'q': text
            }
            
            # 准备请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # 发送请求
            for attempt in range(helper.retry_count):
                try:
                    response = requests.get(
                        url,
                        params=params,
                        headers=headers,
                        timeout=helper.timeout
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        # 提取翻译结果
                        if isinstance(data, list) and len(data) > 0:
                            translated_text = ''
                            for item in data[0]:
                                if isinstance(item, list) and len(item) > 0:
                                    translated_text += item[0]
                            if translated_text:
                                return translated_text
                except Exception as e:
                    logging.warning(f"Google翻译请求异常: {str(e)}")
                
                # 重试前等待
                if attempt < helper.retry_count - 1:
                    time.sleep(helper.retry_interval)
        except Exception as e:
            logging.error(f"Google翻译时发生错误: {str(e)}")
        
        return None


# 创建默认实例
translation_helper = TranslationHelper()

# 导出常用函数
def translate(text: str, target_lang: str = 'zh') -> str:
    """翻译文本的快捷函数"""
    return translation_helper.translate(text, target_lang)