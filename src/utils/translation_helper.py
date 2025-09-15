import logging
import requests
import time

logger = logging.getLogger(__name__)

class TranslationHelper:
    """翻译辅助类"""
    
    @staticmethod
    def translate(text, target_lang='zh-CHS'):
        """翻译文本，支持有道和Google翻译API容灾"""
        # 如果文本为空，直接返回
        if not text or text.strip() == '':
            return text
        
        # 首先尝试使用有道翻译API
        logger.info("使用有道翻译API进行翻译...")
        translated_text = TranslationHelper._youdao_translate(text, target_lang)
        
        # 如果有道翻译API失败，尝试使用Google翻译API
        if translated_text is None:
            logger.info("有道翻译API失败，尝试使用Google翻译API进行容灾...")
            translated_text = TranslationHelper._google_translate(text, target_lang)
        
        # 如果所有翻译API都失败，返回原文
        if translated_text is None or translated_text.strip() == '':
            logger.warning("所有翻译API都失败，返回原文")
            return text
        
        return translated_text
    
    @staticmethod
    def _youdao_translate(text, target_lang='zh-CHS'):
        """使用有道翻译API翻译文本"""
        url = 'https://aidemo.youdao.com/trans'
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                data = {
                    "q": text,
                    "from": "auto", 
                    "to": target_lang
                }
                
                logger.debug(f"发送有道翻译请求，文本长度: {len(text)}")
                resp = requests.post(url, data, timeout=15)
                
                if resp is not None and resp.status_code == 200:
                    resp_json = resp.json()
                    if "translation" in resp_json:
                        translated = "\n".join(str(i) for i in resp_json["translation"])
                        logger.debug(f"有道翻译成功，结果长度: {len(translated)}")
                        return translated
                    else:
                        logger.warning(f"有道翻译API返回不包含translation字段")
                else:
                    logger.warning(f"有道翻译API返回非200状态码: {resp.status_code if resp else '无响应'}")
                    
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"有道翻译API连接错误: {str(e)}")
            except requests.exceptions.Timeout as e:
                logger.warning(f"有道翻译API请求超时: {str(e)}")
            except ValueError as e:
                logger.warning(f"有道翻译API返回格式错误: {str(e)}")
                break  # JSON解析错误不需要重试
            except Exception as e:
                logger.warning(f"有道翻译时发生错误: {str(e)}")
            
            retry_count += 1
            if retry_count <= max_retries:
                logger.info(f"有道翻译失败，尝试第{retry_count+1}次重试...")
                time.sleep(1)  # 重试间隔1秒
        
        logger.warning(f"有道翻译API在{max_retries+1}次尝试后失败")
        return None
    
    @staticmethod
    def _google_translate(text, target_lang='zh-CN'):
        """使用Google翻译API翻译文本"""
        url = 'https://translate.googleapis.com/translate_a/single'
        params = {
            'client': 'gtx',
            'sl': 'auto',  # 源语言自动检测
            'tl': target_lang,  # 目标语言
            'dt': 't',
            'q': text
        }
        
        try:
            logger.debug(f"发送Google翻译请求，文本长度: {len(text)}")
            resp = requests.get(url, params=params, timeout=15)
            
            if resp.status_code == 200:
                resp_json = resp.json()
                if resp_json and isinstance(resp_json, list):
                    # Google翻译API返回的结构需要解析
                    translated_parts = []
                    if resp_json[0] and isinstance(resp_json[0], list):
                        for item in resp_json[0]:
                            if item and item[0]:
                                translated_parts.append(item[0])
                    
                    translated_text = ''.join(translated_parts)
                    if translated_text:
                        logger.debug(f"Google翻译成功，结果长度: {len(translated_text)}")
                        return translated_text
                    else:
                        logger.warning("Google翻译API返回空结果")
            else:
                logger.warning(f"Google翻译API返回非200状态码: {resp.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Google翻译API请求异常: {str(e)}")
        except ValueError as e:
            logger.warning(f"Google翻译API返回格式错误: {str(e)}")
        except Exception as e:
            logger.warning(f"Google翻译时发生错误: {str(e)}")
        
        logger.warning("Google翻译API失败")
        return None
    
    @staticmethod
    def detect_language(text):
        """检测文本语言"""
        # 简单的语言检测，基于常见字符范围
        # 这里可以扩展为使用专业的语言检测API
        chinese_chars = sum(1 for char in text if '\u4e00' <= char <= '\u9fff')
        
        if chinese_chars / len(text) > 0.3:
            return 'zh'
        else:
            return 'en'
    
    @staticmethod
    def is_need_translation(text, source_lang=None, target_lang='zh-CHS'):
        """判断是否需要翻译"""
        # 如果源语言和目标语言相同，不需要翻译
        if source_lang and source_lang.lower().startswith(target_lang.lower().split('-')[0]):
            return False
        
        # 如果没有指定源语言，自动检测
        if not source_lang:
            source_lang = TranslationHelper.detect_language(text)
            if source_lang.lower().startswith(target_lang.lower().split('-')[0]):
                return False
        
        # 如果文本太短，可能不需要翻译
        if len(text) < 10:
            return False
        
        return True

# 创建默认实例
translation_helper = TranslationHelper()

# 导出常用函数
def translate(text, target_lang='zh-CHS'):
    """翻译文本的快捷函数"""
    return TranslationHelper.translate(text, target_lang)