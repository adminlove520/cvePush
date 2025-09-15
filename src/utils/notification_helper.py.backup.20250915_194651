import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional, Union
import json
import time

from src.utils.security_utils import security_utils

logger = logging.getLogger(__name__)

class NotificationSender:
    """通知发送器基类"""
    def __init__(self):
        self.is_enabled = True
    
    def send(self, title: str, content: str, **kwargs) -> bool:
        """发送通知
        
        Args:
            title: 通知标题
            content: 通知内容
            **kwargs: 额外参数
            
        Returns:
            bool: 是否发送成功
        """
        raise NotImplementedError("子类必须实现send方法")

class EmailSender(NotificationSender):
    """邮件通知发送器"""
    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str, sender: str, recipients: list):
        super().__init__()
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.sender = sender
        self.recipients = recipients
    
    def send(self, title: str, content: str, **kwargs) -> bool:
        """发送邮件通知
        
        Args:
            title: 邮件标题
            content: 邮件内容
            **kwargs:
                recipients: 收件人列表（可选，覆盖默认）
                is_html: 是否为HTML内容
            
        Returns:
            bool: 是否发送成功
        """
        if not self.is_enabled:
            logger.debug("邮件通知已禁用")
            return False
        
        try:
            # 创建邮件对象
            message = MIMEMultipart()
            message['From'] = self.sender
            message['To'] = ', '.join(kwargs.get('recipients', self.recipients))
            message['Subject'] = title
            
            # 设置邮件内容
            is_html = kwargs.get('is_html', False)
            if is_html:
                message.attach(MIMEText(content, 'html', 'utf-8'))
            else:
                message.attach(MIMEText(content, 'plain', 'utf-8'))
            
            # 发送邮件
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # 启用TLS加密
                server.login(self.username, self.password)
                text = message.as_string()
                server.sendmail(self.sender, kwargs.get('recipients', self.recipients), text)
            
            logger.info(f"邮件通知发送成功: {title}")
            return True
        except Exception as e:
            logger.error(f"发送邮件通知失败: {str(e)}")
            return False

class DingTalkSender(NotificationSender):
    """钉钉群机器人通知发送器"""
    def __init__(self, webhook_url: str, secret_key: str = None):
        super().__init__()
        self.webhook_url = webhook_url
        self.secret_key = secret_key
    
    def send(self, title: str, content: str, **kwargs) -> bool:
        """发送钉钉群机器人通知
        
        Args:
            title: 通知标题
            content: 通知内容
            **kwargs:
                at_mobiles: 被@的手机号码列表
                at_all: 是否@所有人
            
        Returns:
            bool: 是否发送成功
        """
        if not self.is_enabled:
            logger.debug("钉钉通知已禁用")
            return False
        
        try:
            # 构建请求URL
            url = self.webhook_url
            if self.secret_key:
                # 生成签名
                signature, timestamp = security_utils.get_dingtalk_signature(self.secret_key)
                if signature:
                    url = f"{self.webhook_url}&timestamp={timestamp}&sign={signature}"
                else:
                    logger.warning("生成钉钉签名失败，使用不加密的URL")
            
            # 构建消息体
            message = {
                "msgtype": "text",
                "text": {
                    "content": f"{title}\n{content}"
                },
                "at": {
                    "atMobiles": kwargs.get('at_mobiles', []),
                    "isAtAll": kwargs.get('at_all', False)
                }
            }
            
            # 发送请求
            headers = {'Content-Type': 'application/json'}
            response = requests.post(url, data=json.dumps(message), headers=headers)
            response_json = response.json()
            
            if response_json.get('errcode') == 0:
                logger.info(f"钉钉通知发送成功: {title}")
                return True
            else:
                logger.error(f"发送钉钉通知失败: {response_json.get('errmsg')}")
                return False
        except Exception as e:
            logger.error(f"发送钉钉通知时发生异常: {str(e)}")
            return False

class WeChatWorkSender(NotificationSender):
    """企业微信通知发送器"""
    def __init__(self, webhook_url: str):
        super().__init__()
        self.webhook_url = webhook_url
    
    def send(self, title: str, content: str, **kwargs) -> bool:
        """发送企业微信通知
        
        Args:
            title: 通知标题
            content: 通知内容
            **kwargs:
                mentioned_list: 被@的成员列表
                mentioned_mobile_list: 被@的手机号码列表
            
        Returns:
            bool: 是否发送成功
        """
        if not self.is_enabled:
            logger.debug("企业微信通知已禁用")
            return False
        
        try:
            # 构建消息体
            message = {
                "msgtype": "text",
                "text": {
                    "content": f"{title}\n{content}",
                    "mentioned_list": kwargs.get('mentioned_list', []),
                    "mentioned_mobile_list": kwargs.get('mentioned_mobile_list', [])
                }
            }
            
            # 发送请求
            headers = {'Content-Type': 'application/json'}
            response = requests.post(self.webhook_url, data=json.dumps(message), headers=headers)
            response_json = response.json()
            
            if response_json.get('errcode') == 0:
                logger.info(f"企业微信通知发送成功: {title}")
                return True
            else:
                logger.error(f"发送企业微信通知失败: {response_json.get('errmsg')}")
                return False
        except Exception as e:
            logger.error(f"发送企业微信通知时发生异常: {str(e)}")
            return False

class HTTPWebhookSender(NotificationSender):
    """HTTP Webhook通知发送器"""
    def __init__(self, webhook_url: str, headers: Dict = None, method: str = 'POST'):
        super().__init__()
        self.webhook_url = webhook_url
        self.headers = headers or {'Content-Type': 'application/json'}
        self.method = method.upper()
    
    def send(self, title: str, content: str, **kwargs) -> bool:
        """发送HTTP Webhook通知
        
        Args:
            title: 通知标题
            content: 通知内容
            **kwargs:
                payload: 自定义payload，如果提供则忽略title和content
                timeout: 请求超时时间
            
        Returns:
            bool: 是否发送成功
        """
        if not self.is_enabled:
            logger.debug("HTTP Webhook通知已禁用")
            return False
        
        try:
            # 获取payload
            payload = kwargs.get('payload')
            if payload is None:
                # 构建默认payload
                if self.headers.get('Content-Type') == 'application/json':
                    payload = {
                        'title': title,
                        'content': content,
                        'timestamp': int(time.time())
                    }
                else:
                    payload = f"title={title}&content={content}"
            
            # 发送请求
            timeout = kwargs.get('timeout', 10)
            if self.method == 'POST':
                response = requests.post(self.webhook_url, headers=self.headers, data=payload if isinstance(payload, str) else json.dumps(payload), timeout=timeout)
            elif self.method == 'GET':
                if isinstance(payload, dict):
                    response = requests.get(self.webhook_url, headers=self.headers, params=payload, timeout=timeout)
                else:
                    response = requests.get(self.webhook_url, headers=self.headers, timeout=timeout)
            else:
                logger.error(f"不支持的HTTP方法: {self.method}")
                return False
            
            if response.status_code == 200:
                logger.info(f"HTTP Webhook通知发送成功: {title}")
                return True
            else:
                logger.error(f"发送HTTP Webhook通知失败，状态码: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"发送HTTP Webhook通知时发生异常: {str(e)}")
            return False

class NotificationManager:
    """通知管理器，支持管理多个通知发送器"""
    def __init__(self):
        self.senders = []
    
    def add_sender(self, sender: NotificationSender) -> None:
        """添加通知发送器
        
        Args:
            sender: 通知发送器实例
        """
        self.senders.append(sender)
    
    def remove_sender(self, sender: NotificationSender) -> None:
        """移除通知发送器
        
        Args:
            sender: 通知发送器实例
        """
        if sender in self.senders:
            self.senders.remove(sender)
    
    def send_all(self, title: str, content: str, **kwargs) -> Dict[NotificationSender, bool]:
        """通过所有通知发送器发送通知
        
        Args:
            title: 通知标题
            content: 通知内容
            **kwargs: 额外参数，将传递给每个发送器的send方法
            
        Returns:
            Dict[NotificationSender, bool]: 每个发送器的发送结果
        """
        results = {}
        
        for sender in self.senders:
            try:
                results[sender] = sender.send(title, content, **kwargs)
            except Exception as e:
                logger.error(f"通过{sender.__class__.__name__}发送通知时发生异常: {str(e)}")
                results[sender] = False
        
        return results
    
    def send_to(self, title: str, content: str, sender_types: Union[type, list], **kwargs) -> Dict[NotificationSender, bool]:
        """发送通知到特定类型的发送器
        
        Args:
            title: 通知标题
            content: 通知内容
            sender_types: 发送器类型或类型列表
            **kwargs: 额外参数
            
        Returns:
            Dict[NotificationSender, bool]: 每个发送器的发送结果
        """
        if not isinstance(sender_types, list):
            sender_types = [sender_types]
        
        results = {}
        
        for sender in self.senders:
            if isinstance(sender, tuple(sender_types)):
                try:
                    results[sender] = sender.send(title, content, **kwargs)
                except Exception as e:
                    logger.error(f"通过{sender.__class__.__name__}发送通知时发生异常: {str(e)}")
                    results[sender] = False
        
        return results
    
    def enable_all(self) -> None:
        """启用所有通知发送器"""
        for sender in self.senders:
            sender.is_enabled = True
        logger.info("已启用所有通知发送器")
    
    def disable_all(self) -> None:
        """禁用所有通知发送器"""
        for sender in self.senders:
            sender.is_enabled = False
        logger.info("已禁用所有通知发送器")

# 创建默认实例
notification_manager = NotificationManager()