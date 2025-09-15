import os
import logging
import sqlite3
from datetime import datetime, timedelta, UTC

logger = logging.getLogger(__name__)

class DatabaseManager:
    """数据库管理类，负责与SQLite数据库交互"""
    
    def __init__(self, db_path=None):
        """初始化数据库管理器"""
        # 默认数据库路径
        if db_path is None:
            db_path = os.path.join('data', 'db', 'vulns.db')
        
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
            
            # 创建漏洞表，包含tags列
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulns (
                    id TEXT PRIMARY KEY,
                    published_date TEXT,
                    cvss_score REAL,
                    description TEXT,
                    vector_string TEXT,
                    refs TEXT,
                    source TEXT,
                    tags TEXT DEFAULT '未分类'
                )
            ''')
            
            # 创建索引以提高查询性能
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_published_date ON vulns (published_date)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cvss_score ON vulns (cvss_score)')
            
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
            
            # 检查数据库是否有tags列
            cursor.execute("PRAGMA table_info(vulns)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # 根据是否有tags列选择不同的查询语句
            if 'tags' in columns:
                cursor.execute("SELECT id, published_date, cvss_score, description, vector_string, refs, source, tags FROM vulns WHERE id=?", (cve_id,))
            else:
                cursor.execute("SELECT id, published_date, cvss_score, description, vector_string, refs, source FROM vulns WHERE id=?", (cve_id,))
            
            row = cursor.fetchone()
            if row:
                vuln_dict = {
                    'id': row[0],
                    'published_date': row[1],
                    'cvss_score': row[2],
                    'description': row[3],
                    'vector_string': row[4],
                    'refs': row[5],
                    'source': row[6]
                }
                # 如果查询结果包含tags列，则添加tags字段
                if len(row) > 7:
                    vuln_dict['tags'] = row[7]
                
                return vuln_dict
            return None
        except Exception as e:
            logger.error(f"获取CVE信息失败: {str(e)}")
            return None
        finally:
            conn.close()
    
    def is_new_vuln(self, vuln_id):
        """检查漏洞是否是新漏洞（数据库中不存在）"""
        conn = self.connect()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM vulns WHERE id=?", (vuln_id,))
            exists = cursor.fetchone() is not None
            return not exists
        except Exception as e:
            logger.error(f"检查漏洞是否存在时出错: {str(e)}")
            return False
        finally:
            conn.close()
    
    def save_vuln(self, vuln_info):
        """保存漏洞信息到数据库"""
        conn = self.connect()
        if not conn:
            return False
        
        try:
            # 确保表存在
            self.ensure_table_exists()
            
            cursor = conn.cursor()
            
            # 检查数据库是否有tags列
            cursor.execute("PRAGMA table_info(vulns)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'tags' in columns:
                # 如果有tags列，插入包含tags的完整数据
                cursor.execute("INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          (vuln_info['id'], vuln_info['published_date'], vuln_info['cvss_score'],
                           vuln_info['description'], vuln_info['vector_string'],
                           vuln_info['refs'], vuln_info['source'], vuln_info.get('tags', '未分类')))
            else:
                # 如果没有tags列，插入不包含tags的数据
                cursor.execute("INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (vuln_info['id'], vuln_info['published_date'], vuln_info['cvss_score'],
                           vuln_info['description'], vuln_info['vector_string'],
                           vuln_info['refs'], vuln_info['source']))
            conn.commit()
            logger.info(f"漏洞已保存到数据库: {vuln_info['id']}")
            return True
        except sqlite3.IntegrityError:
            # 忽略主键冲突错误
            logger.warning(f"漏洞 {vuln_info['id']} 已存在于数据库中")
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
            
            # 检查数据库是否有tags列
            cursor.execute("PRAGMA table_info(vulns)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # 根据是否有tags列选择不同的查询语句
            if 'tags' in columns:
                cursor.execute("""
                    SELECT id, published_date, cvss_score, description, vector_string, refs, source, tags 
                    FROM vulns 
                    WHERE published_date >= ? AND published_date < ?
                    ORDER BY cvss_score DESC
                """, (today_str, tomorrow_str))
            else:
                cursor.execute("""
                    SELECT id, published_date, cvss_score, description, vector_string, refs, source 
                    FROM vulns 
                    WHERE published_date >= ? AND published_date < ?
                    ORDER BY cvss_score DESC
                """, (today_str, tomorrow_str))
            
            vulns = []
            for row in cursor.fetchall():
                vuln_dict = {
                    'id': row[0],
                    'published_date': row[1],
                    'cvss_score': row[2],
                    'description': row[3],
                    'vector_string': row[4],
                    'refs': row[5],
                    'source': row[6]
                }
                # 如果查询结果包含tags列，则添加tags字段
                if len(row) > 7:
                    vuln_dict['tags'] = row[7]
                
                vulns.append(vuln_dict)
            
            logger.info(f"获取到 {len(vulns)} 个今日漏洞")
            return vulns
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
            
            # 检查数据库是否有tags列
            cursor.execute("PRAGMA table_info(vulns)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # 根据是否有tags列选择不同的查询语句
            if 'tags' in columns:
                cursor.execute("""
                    SELECT id, published_date, cvss_score, description, vector_string, refs, source, tags 
                    FROM vulns 
                    WHERE published_date >= ? AND published_date < ?
                    ORDER BY cvss_score DESC
                """, (start_date, end_date))
            else:
                cursor.execute("""
                    SELECT id, published_date, cvss_score, description, vector_string, refs, source 
                    FROM vulns 
                    WHERE published_date >= ? AND published_date < ?
                    ORDER BY cvss_score DESC
                """, (start_date, end_date))
            
            vulns = []
            for row in cursor.fetchall():
                vuln_dict = {
                    'id': row[0],
                    'published_date': row[1],
                    'cvss_score': row[2],
                    'description': row[3],
                    'vector_string': row[4],
                    'refs': row[5],
                    'source': row[6]
                }
                # 如果查询结果包含tags列，则添加tags字段
                if len(row) > 7:
                    vuln_dict['tags'] = row[7]
                
                vulns.append(vuln_dict)
            
            logger.info(f"获取到 {len(vulns)} 个指定日期范围内的漏洞")
            return vulns
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

# 创建默认实例
db_manager = DatabaseManager()

# 兼容旧的函数调用方式
def get_cve_info_from_db(cve_id):
    """兼容旧的函数调用方式"""
    return db_manager.get_cve_info(cve_id)