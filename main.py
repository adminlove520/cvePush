#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE_PushService - 主入口文件
"""

import os
import sys
import argparse
import logging
import time
from datetime import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import settings, setup_logging
from src.monitor.poc_monitor import poc_monitor
from src.core.cve_collector import cve_collector
from src.core.cve_processor import cve_processor
from src.utils.db_manager import db_manager

logger = logging.getLogger(__name__)

def init_app() -> None:
    """初始化应用"""
    # 初始化日志
    log_file = settings.get('LOGGING.file', 'logs/cve_push_service.log')
    log_level = settings.get('LOGGING.level', 'INFO')
    
    # 确保日志目录存在
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 设置日志
    setup_logging(
        log_level=log_level,
        log_file=log_file,
        enable_console=True,
        enable_file=True
    )
    
    # 验证配置
    if not settings.validate():
        logger.error("配置验证失败，程序即将退出")
        sys.exit(1)
    
    # 初始化数据库
    db_manager.ensure_table_exists()

    logger.info(f"{settings.get('APP.name', 'CVE_PushService')} v{settings.get('APP.version', '1.0.0')} 已启动")

def process_single_cve(cve_id: str) -> None:
    """处理单个CVE
    
    Args:
        cve_id: CVE标识符
    """
    try:
        logger.info(f"开始处理单个CVE: {cve_id}")
        
        # 获取CVE信息
        cve_data = cve_collector.get_cve_by_id(cve_id)
        if not cve_data:
            logger.error(f"未找到CVE信息: {cve_id}")
            return
        
        # 搜索POC信息
        poc_info = poc_monitor.search_poc_for_cve(cve_id)
        cve_data['poc_info'] = poc_info
        
        # 处理CVE数据
        processed_cve = cve_processor.process_cve(cve_data)
        
        # 更新数据库中的POC信息
        import json
        db_manager.update_poc_info(cve_id, json.dumps(poc_info))
        
        logger.info(f"CVE处理完成: {cve_id}")
        
        # 输出处理结果摘要
        print(f"\nCVE处理结果摘要:")
        print(f"ID: {processed_cve.get('id', '未知')}")
        print(f"严重性: {processed_cve.get('severity_level', '未知')}")
        print(f"CVSS评分: {processed_cve.get('cvss_score', '未知')}")
        print(f"描述: {processed_cve.get('description', '暂无描述')[:100]}...")
        print(f"是否有POC: {'是' if poc_info.get('has_poc', False) else '否'}")
        if 'report_path' in processed_cve:
            print(f"报告路径: {processed_cve['report_path']}")
    except Exception as e:
        logger.error(f"处理CVE时发生错误: {str(e)}", exc_info=True)
        print(f"处理CVE失败: {str(e)}", file=sys.stderr)

def process_daily_vulns() -> None:
    """处理当日漏洞"""
    try:
        logger.info("开始处理当日漏洞")
        
        # 执行每日检查
        processed_count = poc_monitor.run_daily_check()
        
        # 生成每日报告
        report_path = poc_monitor.generate_daily_report()
        
        logger.info(f"当日漏洞处理完成，共处理 {processed_count} 个漏洞")
        
        # 输出处理结果摘要
        print(f"\n当日漏洞处理结果摘要:")
        print(f"共处理漏洞数量: {processed_count}")
        if report_path:
            print(f"每日报告已生成: {report_path}")
    except Exception as e:
        logger.error(f"处理当日漏洞时发生错误: {str(e)}", exc_info=True)
        print(f"处理当日漏洞失败: {str(e)}", file=sys.stderr)

def fetch_full_year_data(year=None):
    """获取指定年份的全量CVE数据并保存为Markdown文件"""
    try:
        collector = cve_collector
        
        # 如果没有指定年份，默认使用当前年份
        target_year = year if year else datetime.now().year
        
        # 获取全量数据
        year_data = collector.fetch_full_year_data(year=target_year)
        
        # 保存为Markdown文件
        if year_data and year_data.get('data'):
            file_path = collector.save_full_year_data_to_markdown(year_data)
            if file_path:
                logger.info(f"全量数据已成功保存到文件: {file_path}")
                return True
            else:
                logger.error("保存全量数据失败")
                return False
        else:
            logger.warning(f"未获取到{target_year}年的有效CVE数据")
            return False
    except Exception as e:
        logger.error(f"获取全量数据时发生错误: {str(e)}")
        return False

def start_monitoring() -> None:
    """启动监控服务"""
    try:
        logger.info("启动监控服务")
        
        # 启动POC监控
        poc_monitor.start_monitoring()
    except KeyboardInterrupt:
        logger.info("监控服务已手动停止")
        print("\n监控服务已手动停止")
    except Exception as e:
        logger.error(f"监控服务发生错误: {str(e)}", exc_info=True)
        print(f"监控服务发生错误: {str(e)}", file=sys.stderr)

def generate_daily_report(date: str = None) -> None:
    """生成指定日期的每日报告
    
    Args:
        date: 日期（格式：YYYY-MM-DD）
    """
    try:
        logger.info(f"开始生成每日报告，日期: {date or '当天'}")
        
        # 生成报告
        report_path = poc_monitor.generate_daily_report(date)
        
        if report_path:
            logger.info(f"每日报告生成成功: {report_path}")
            print(f"每日报告已生成: {report_path}")
        else:
            logger.warning(f"未能生成每日报告")
            print(f"未能生成每日报告")
    except Exception as e:
        logger.error(f"生成每日报告时发生错误: {str(e)}", exc_info=True)
        print(f"生成每日报告失败: {str(e)}", file=sys.stderr)

def main() -> None:
    """主函数"""
    # 初始化应用
    init_app()
    
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description='CVE Push Service - 监控和推送CVE漏洞信息')
    
    # 添加子命令
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 处理单个CVE的命令
    cve_parser = subparsers.add_parser('cve', help='处理单个CVE')
    cve_parser.add_argument('cve_id', help='CVE标识符，如 CVE-2023-1234')
    
    # 处理当日漏洞的命令
    daily_parser = subparsers.add_parser('daily', help='处理当日漏洞')
    
    # 启动监控服务的命令
    monitor_parser = subparsers.add_parser('monitor', help='启动持续监控服务')
    
    # 生成每日报告的命令
    report_parser = subparsers.add_parser('report', help='生成每日报告')
    report_parser.add_argument('--date', help='指定日期（格式：YYYY-MM-DD），默认为当天')
    
    # 添加全量数据获取命令
    full_year_parser = subparsers.add_parser('full-year', help='获取指定年份的全量CVE数据并保存为Markdown文件')
    full_year_parser.add_argument('--year', type=int, default=None, help='指定要获取数据的年份，默认为当前年份')
    
    # 解析命令行参数
    args = parser.parse_args()
    
    # 根据命令执行相应的功能
    if args.command == 'cve':
        process_single_cve(args.cve_id)
    elif args.command == 'daily':
        process_daily_vulns()
    elif args.command == 'monitor':
        start_monitoring()
    elif args.command == 'report':
        generate_daily_report(args.date)
    elif args.command == 'full-year':
        fetch_full_year_data(args.year)
    else:
        # 如果没有指定命令，显示帮助信息
        parser.print_help()

if __name__ == '__main__':
    main()