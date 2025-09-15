#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import logging
from datetime import datetime, timedelta, UTC

logger = logging.getLogger("DBUtils")

class DatabaseManager:
    """数据库管理类，提供统一的数据库操作接口"""
    
    def __init__(self, db_path='vulns.db'):
        self.db_path = db_path
    
    def connect(self):
        """建立数据库连接"""
        try:
            conn = sqlite3.connect(self.db_path)
            return conn
        except Exception as e:
            logger.error(f"数据库连接失败: {str(e)}")
            return None
    
    def ensure_table_exists(self, table_name='vulns'):
        """确保指定的表存在，如果不存在则创建"""
        conn = self.connect()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            # 检查表是否存在
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            table_exists = cursor.fetchone() is not None
            
            if not table_exists:
                # 如果表不存在，创建表
                cursor.execute('''CREATE TABLE vulns
                             (id TEXT PRIMARY KEY, 
                              published_date TEXT, 
                              cvss_score REAL, 
                              description TEXT, 
                              vector_string TEXT,
                              refs TEXT,
                              source TEXT,
                              tags TEXT)''')
                conn.commit()
                logger.info("创建vulns表")
            
            # 确保表有tags列
            cursor.execute("PRAGMA table_info(vulns)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'tags' not in columns:
                # 添加tags列
                cursor.execute("ALTER TABLE vulns ADD COLUMN tags TEXT")
                conn.commit()
                logger.info("添加tags列到vulns表")
            
            return True
        except Exception as e:
            logger.error(f"确保表存在时出错: {str(e)}")
            return False
        finally:
            conn.close()
    
    def get_cve_info(self, cve_id):
        """根据CVE ID从数据库获取漏洞信息"""
        conn = self.connect()
        if not conn:
            return None
        
        try:
            # 确保表存在
            self.ensure_table_exists()
            
            cursor = conn.cursor()
            # 查询数据库中的CVE信息
            cursor.execute("SELECT id, published_date, cvss_score, description, vector_string, refs, source, tags FROM vulns WHERE id = ?", (cve_id,))
            row = cursor.fetchone()
            
            if row:
                # 数据库中有记录，返回完整信息
                return {
                    'id': row[0],
                    'published_date': row[1],
                    'cvss_score': row[2],
                    'description': row[3],
                    'vector_string': row[4],
                    'refs': row[5],
                    'source': row[6],
                    'tags': row[7]
                }
            else:
                # 数据库中没有记录
                logger.warning(f"CVE {cve_id} 未在数据库中找到")
                return None
        except Exception as e:
            logger.error(f"从数据库获取CVE信息失败: {str(e)}")
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
            
            return vulns
        except Exception as e:
            logger.error(f"获取当天漏洞信息失败: {str(e)}")
            return []
        finally:
            conn.close()

# 提供默认的数据库管理器实例
db_manager = DatabaseManager()

# 兼容旧的函数调用方式
def get_cve_info_from_db(cve_id):
    """兼容旧的函数调用方式"""
    return db_manager.get_cve_info(cve_id)

# 导出主要函数
export = {
    'DatabaseManager': DatabaseManager,
    'db_manager': db_manager,
    'get_cve_info_from_db': get_cve_info_from_db
}