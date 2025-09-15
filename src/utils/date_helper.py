import logging
from datetime import datetime, timedelta, UTC

logger = logging.getLogger(__name__)

class DateHelper:
    """日期处理辅助类"""
    
    @staticmethod
    def get_current_year():
        """获取当前年份"""
        return datetime.now(UTC).year
    
    @staticmethod
    def get_week_date_format():
        """获取周格式的日期字符串 (YYYY-MM-DD_YYYY-MM-DD)"""
        today = datetime.now(UTC).date()
        # 计算本周一
        monday = today - timedelta(days=today.weekday())
        # 计算本周日
        sunday = monday + timedelta(days=6)
        
        return f"{monday.strftime('%Y-%m-%d')}_{sunday.strftime('%Y-%m-%d')}"
    
    @staticmethod
    def get_simple_week_date_format():
        """获取简化的周格式 (YYYY-wW)，其中W为周数"""
        today = datetime.now(UTC).date()
        year = today.year
        week_number = today.isocalendar()[1]
        
        return f"{year}-w{week_number}"
    
    @staticmethod
    def format_datetime(dt, format_str='%Y-%m-%d %H:%M:%S'):
        """格式化日期时间"""
        if isinstance(dt, str):
            try:
                # 尝试将字符串解析为datetime对象
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except ValueError:
                logger.warning(f"无法解析日期时间字符串: {dt}")
                return dt
        
        return dt.strftime(format_str)
    
    @staticmethod
    def parse_datetime(dt_str):
        """解析日期时间字符串"""
        try:
            # 支持ISO格式，包括带Z时区的格式
            if dt_str.endswith('Z'):
                dt_str = dt_str.replace('Z', '+00:00')
            return datetime.fromisoformat(dt_str)
        except ValueError:
            logger.warning(f"无法解析日期时间字符串: {dt_str}")
            return None
    
    @staticmethod
    def get_date_range(days=1):
        """获取日期范围，默认返回今天和明天"""
        today = datetime.now(UTC).date()
        tomorrow = today + timedelta(days=days)
        
        return {
            'start': today.strftime('%Y-%m-%d'),
            'end': tomorrow.strftime('%Y-%m-%d')
        }
    
    @staticmethod
    def is_same_day(dt1, dt2):
        """判断两个日期是否是同一天"""
        if isinstance(dt1, str):
            dt1 = DateHelper.parse_datetime(dt1)
        if isinstance(dt2, str):
            dt2 = DateHelper.parse_datetime(dt2)
        
        if dt1 is None or dt2 is None:
            return False
        
        return dt1.date() == dt2.date()
    
    @staticmethod
    def get_time_ago_text(dt):
        """获取相对时间描述，如'3小时前'，'2天前'"""
        if isinstance(dt, str):
            dt = DateHelper.parse_datetime(dt)
        
        if dt is None:
            return '未知时间'
        
        now = datetime.now(UTC)
        delta = now - dt
        
        seconds = delta.total_seconds()
        if seconds < 60:
            return f'{int(seconds)}秒前'
        elif seconds < 3600:
            return f'{int(seconds/60)}分钟前'
        elif seconds < 86400:
            return f'{int(seconds/3600)}小时前'
        elif seconds < 604800:
            return f'{int(seconds/86400)}天前'
        elif seconds < 2592000:
            return f'{int(seconds/604800)}周前'
        elif seconds < 31536000:
            return f'{int(seconds/2592000)}个月前'
        else:
            return f'{int(seconds/31536000)}年前'

# 创建默认实例
date_helper = DateHelper()