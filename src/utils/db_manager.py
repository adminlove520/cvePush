import os
import logging
import sqlite3
import json
from datetime import datetime, timedelta, UTC

import src.utils.cache_helper as cache_helper
from src.config import settings

logger = logging.getLogger(__name__)

class DatabaseManager:
    """数据库管理类，负责与SQLite数据库交互"""
    
    def __init__(self, db_path=None):
        """初始化数据库管理器"""
        # 默认数据库路径
        if db_path is None:
            db_path = settings.get('DATABASE.path', os.path.join('data', 'db', 'vulns.db'))
        
        self.db_path = db_path
        # 确保数据库目录存在
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir)
                logger.info(f"创建数据库目录: {db_dir}")
            except Exception as e:
                logger.error(f"创建数据库目录失败: {str(e)}")
    
    def connect(self):
        """连接到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            # 启用外键约束
            conn.execute("PRAGMA foreign_keys = ON")
            return conn
        except Exception as e:
            logger.error(f"数据库连接失败: {str(e)}")
            return None
    
    def ensure_table_exists(self):
        """确保数据表存在，如果不存在则创建"""
        conn = self.connect()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # 创建漏洞表，与cve_collector中保存的数据结构匹配
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulns (
                    id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    published_date TEXT,
                    last_modified_date TEXT,
                    cvss_score REAL,
                    vuln_references TEXT,
                    tags TEXT,
                    source TEXT,
                    is_new INTEGER,
                    poc_info TEXT,
                    created_at TEXT
                )
            ''')
            
            # 创建索引以提高查询性能
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_published_date ON vulns (published_date)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cvss_score ON vulns (cvss_score)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON vulns (severity)')
            
            conn.commit()
            logger.info("数据库表已确保存在")
            return True
        except Exception as e:
            logger.error(f"创建数据库表失败: {str(e)}")
            return False
        finally:
            conn.close()
    
    def get_cve_info(self, cve_id):
        """根据CVE ID获取漏洞信息"""
        conn = self.connect()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # 查询所有字段
            cursor.execute("SELECT * FROM vulns WHERE id=?", (cve_id,))
            
            row = cursor.fetchone()
            if row:
                # 直接返回原始数据行，保持与poc_monitor.py中的使用方式一致
                # poc_monitor.py中期望的是元组格式，而不是字典
                return row
            return None
        except Exception as e:
            logger.error(f"获取CVE信息失败: {str(e)}")
            return None
        finally:
            conn.close()
    
    def is_new_vuln(self, vuln_id, published_date=None):
        """检查漏洞是否是新漏洞
        
        Args:
            vuln_id: 漏洞ID
            published_date: 漏洞发布日期（可选）
            
        Returns:
            bool: 是否是新漏洞
        """
        conn = self.connect()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # 首先检查漏洞是否存在
            cursor.execute("SELECT published_date FROM vulns WHERE id=?", (vuln_id,))
            row = cursor.fetchone()
            
            # 如果漏洞不存在，肯定是新漏洞
            if not row:
                return True
            
            # 如果提供了发布日期，检查该漏洞是否是近期发布的
            # 只有近期发布的漏洞才应该被视为"新"漏洞并触发通知
            if published_date:
                try:
                    # 解析发布日期
                    if 'Z' in published_date:
                        pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    elif '+' in published_date or '-' in published_date.split('T')[1]:
                        pub_date = datetime.fromisoformat(published_date)
                    else:
                        # 尝试多种格式解析
                        try:
                            pub_date = datetime.fromisoformat(published_date).replace(tzinfo=UTC)
                        except ValueError:
                            # 使用strptime尝试常见格式
                            formats = ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d']
                            pub_date = None
                            for fmt in formats:
                                try:
                                    pub_date = datetime.strptime(published_date, fmt).replace(tzinfo=UTC)
                                    break
                                except ValueError:
                                    continue
                except Exception as e:
                    logger.warning(f"解析发布日期失败: {published_date}, 错误: {str(e)}")
                    return False
                
                # 如果成功解析了发布日期，检查是否在24小时内
                if pub_date:
                    # 计算24小时前的时间点
                    one_day_ago = datetime.now(UTC) - timedelta(days=1)
                    # 只对24小时内发布的漏洞触发通知
                    return pub_date >= one_day_ago
            
            # 如果没有提供发布日期或者日期解析失败，则认为不是新漏洞
            return False
        except Exception as e:
            logger.error(f"检查漏洞是否存在时出错: {str(e)}")
            return False
        finally:
            conn.close()
    
    def save_vuln(self, *args):
        """保存漏洞信息到数据库
        
        支持两种调用方式:
        1. save_vuln(vuln_info_dict) - 传入字典
        2. save_vuln(id, description, severity, published_date, last_modified_date, cvss_score, references, tags, source, is_new, poc_info, created_at) - 传入位置参数
        """
        conn = self.connect()
        if not conn:
            return False
        
        try:
            # 确保表存在
            self.ensure_table_exists()
            
            cursor = conn.cursor()
            
            # 处理参数
            if len(args) == 1 and isinstance(args[0], dict):
                # 传入的是字典
                vuln_info = args[0]
                values = (
                    vuln_info.get('id', ''),
                    vuln_info.get('description', ''),
                    vuln_info.get('severity', 'UNKNOWN'),
                    vuln_info.get('published_date', ''),
                    vuln_info.get('last_modified_date', ''),
                    vuln_info.get('cvss_score', 0.0),
                    json.dumps(vuln_info.get('references', [])),
                    json.dumps(vuln_info.get('tags', [])),
                    vuln_info.get('source', 'NVD'),
                    1 if vuln_info.get('is_new', True) else 0,
                    json.dumps(vuln_info.get('poc_info', {})),
                    vuln_info.get('created_at', datetime.now().isoformat())
                )
            else:
                # 传入的是位置参数
                values = args
            
            # 插入数据 - 使用列名列表指定插入的列，避免顺序问题
            cursor.execute("INSERT INTO vulns (id, description, severity, published_date, last_modified_date, cvss_score, vuln_references, tags, source, is_new, poc_info, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", values)
            conn.commit()
            logger.info(f"漏洞已保存到数据库: {values[0]}")
            return True
        except sqlite3.IntegrityError:
            # 忽略主键冲突错误
            logger.warning(f"漏洞 {values[0]} 已存在于数据库中")
            return False
        except Exception as e:
            logger.error(f"保存漏洞信息到数据库失败: {str(e)}")
            return False
        finally:
            conn.close()
    
    def get_today_vulnerabilities(self):
        """获取当天日期的漏洞信息"""
        conn = self.connect()
        if not conn:
            return []
        
        try:
            # 计算今天的日期范围（UTC时间）
            today = datetime.now(UTC).date()
            tomorrow = today + timedelta(days=1)
            
            # 格式化日期字符串
            today_str = today.strftime('%Y-%m-%d')
            tomorrow_str = tomorrow.strftime('%Y-%m-%d')
            
            cursor = conn.cursor()
            
            # 查询当天的所有漏洞
            cursor.execute("""
                SELECT * 
                FROM vulns 
                WHERE published_date >= ? AND published_date < ?
            """, (today_str, tomorrow_str))
            
            # 直接返回查询结果的原始行数据
            # 因为在poc_monitor.py的generate_daily_report方法中，期望使用元组格式的数据
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"获取当天漏洞信息失败: {str(e)}")
            return []
        finally:
            conn.close()
    
    def get_vulnerabilities_by_date_range(self, start_date, end_date):
        """获取指定日期范围内的漏洞信息"""
        conn = self.connect()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            
            # 查询指定日期范围内的所有漏洞
            cursor.execute("""
                SELECT * 
                FROM vulns 
                WHERE published_date >= ? AND published_date < ?
                ORDER BY cvss_score DESC
            """, (start_date, end_date))
            
            # 直接返回查询结果的原始行数据
            # 与get_today_vulnerabilities方法保持一致
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"获取指定日期范围内的漏洞信息失败: {str(e)}")
            return []
        finally:
            conn.close()
    
    def get_vulnerability_count(self):
        """获取数据库中漏洞的总数量"""
        conn = self.connect()
        if not conn:
            return 0
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM vulns")
            count = cursor.fetchone()[0]
            return count
        except Exception as e:
            logger.error(f"获取漏洞数量失败: {str(e)}")
            return 0
        finally:
            conn.close()
    
    def update_vuln_tags(self, cve_id, tags):
        """更新漏洞的标签信息"""
        conn = self.connect()
        if not conn:
            return False
        
        try:
            # 检查数据库是否有tags列
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(vulns)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'tags' not in columns:
                logger.warning("数据库表中没有tags列，无法更新标签")
                return False
            
            cursor.execute("UPDATE vulns SET tags=? WHERE id=?", (tags, cve_id))
            conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"漏洞标签已更新: {cve_id}, 标签: {tags}")
                return True
            else:
                logger.warning(f"未找到漏洞: {cve_id}，无法更新标签")
                return False
        except Exception as e:
            logger.error(f"更新漏洞标签失败: {str(e)}")
            return False
        finally:
            conn.close()
    
    def update_poc_info(self, cve_id, poc_info):
        """更新漏洞的POC信息
        
        Args:
            cve_id: CVE标识符
            poc_info: POC信息（JSON字符串）
            
        Returns:
            bool: 是否更新成功
        """
        conn = self.connect()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE vulns SET poc_info=? WHERE id=?", (poc_info, cve_id))
            conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"漏洞POC信息已更新: {cve_id}")
                return True
            else:
                logger.warning(f"未找到漏洞: {cve_id}，无法更新POC信息")
                return False
        except Exception as e:
            logger.error(f"更新漏洞POC信息失败: {str(e)}")
            return False
        finally:
            conn.close()

    def get_vulnerabilities_by_date(self, date):
        """根据日期获取漏洞信息"""
        # 计算当天的日期范围
        start_date = date
        # 计算次日的日期
        from datetime import datetime, timedelta
        try:
            date_obj = datetime.strptime(date, '%Y-%m-%d')
            next_day = date_obj + timedelta(days=1)
            end_date = next_day.strftime('%Y-%m-%d')
        except ValueError:
            logger.error(f"无效的日期格式: {date}")
            return []
        
        # 调用已有的日期范围查询方法
        return self.get_vulnerabilities_by_date_range(start_date, end_date)

# 创建默认实例
db_manager = DatabaseManager()

# 兼容旧的函数调用方式
def get_cve_info_from_db(cve_id):
    """兼容旧的函数调用方式"""
    return db_manager.get_cve_info(cve_id)