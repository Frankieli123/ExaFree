"""
统计数据库操作 - 使用 storage.py 的统一数据库连接
"""
import time
from datetime import datetime
from typing import Dict, Tuple
import asyncio
from collections import defaultdict
from core.storage import _get_sqlite_conn, _sqlite_lock


class StatsDatabase:
    """统计数据库管理类 - 使用统一的 data.db"""

    async def insert_request_log(
        self,
        timestamp: float,
        model: str,
        ttfb_ms: int = None,
        total_ms: int = None,
        status: str = "success",
        status_code: int = None,
        user_id: str = None,
        user_name: str = None,
    ):
        """插入请求记录"""
        def _insert():
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                conn.execute(
                    """
                    INSERT INTO request_logs
                    (timestamp, model, ttfb_ms, total_ms, status, status_code, user_id, user_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (int(timestamp), model, ttfb_ms, total_ms, status, status_code, user_id, user_name)
                )
                conn.commit()

        await asyncio.to_thread(_insert)

    async def get_stats_by_time_range(self, time_range: str = "24h") -> Dict:
        """按时间范围获取统计数据"""
        def _query():
            now = time.time()
            if time_range == "24h":
                start_time = now - 24 * 3600
                bucket_size = 3600
            elif time_range == "7d":
                start_time = now - 7 * 24 * 3600
                bucket_size = 6 * 3600
            elif time_range == "30d":
                start_time = now - 30 * 24 * 3600
                bucket_size = 24 * 3600
            else:
                start_time = now - 24 * 3600
                bucket_size = 3600

            conn = _get_sqlite_conn()
            with _sqlite_lock:
                rows = conn.execute(
                    """
                    SELECT timestamp, model, ttfb_ms, total_ms, status, status_code
                    FROM request_logs
                    WHERE timestamp >= ?
                    ORDER BY timestamp
                    """,
                    (int(start_time),)
                ).fetchall()

            # 数据分桶
            buckets = defaultdict(lambda: {
                "total": 0, "failed": 0,
                "apis": defaultdict(int),
                "api_ttfb": defaultdict(list),
                "api_total": defaultdict(list)
            })

            for row in rows:
                ts, model, ttfb, total, status, status_code = row
                bucket_key = int((ts - start_time) // bucket_size)
                bucket = buckets[bucket_key]

                bucket["total"] += 1
                bucket["apis"][model] += 1

                if status != "success":
                    bucket["failed"] += 1

                if status == "success" and ttfb is not None and total is not None:
                    bucket["api_ttfb"][model].append(ttfb)
                    bucket["api_total"][model].append(total)

            # 生成结果
            num_buckets = int((now - start_time) // bucket_size) + 1
            labels = []
            total_requests = []
            failed_requests = []

            # 先收集所有出现过的接口
            all_apis = set()
            for bucket in buckets.values():
                all_apis.update(bucket["apis"].keys())
                all_apis.update(bucket["api_ttfb"].keys())
                all_apis.update(bucket["api_total"].keys())

            # 初始化每个接口的数据列表
            api_requests = {api_name: [] for api_name in all_apis}
            api_ttfb_times = {api_name: [] for api_name in all_apis}
            api_total_times = {api_name: [] for api_name in all_apis}

            # 遍历每个时间桶
            for i in range(num_buckets):
                bucket_time = start_time + i * bucket_size
                dt = datetime.fromtimestamp(bucket_time)

                if time_range == "24h":
                    labels.append(dt.strftime("%H:00"))
                elif time_range == "7d":
                    labels.append(dt.strftime("%m-%d %H:00"))
                else:
                    labels.append(dt.strftime("%m-%d"))

                bucket = buckets[i]
                total_requests.append(bucket["total"])
                failed_requests.append(bucket["failed"])

                # 为每个接口添加数据（存在则添加实际值，不存在则添加0）
                for api_name in all_apis:
                    # 请求数
                    api_requests[api_name].append(bucket["apis"].get(api_name, 0))

                    # TTFB平均时间
                    if api_name in bucket["api_ttfb"] and bucket["api_ttfb"][api_name]:
                        avg_ttfb = sum(bucket["api_ttfb"][api_name]) / len(bucket["api_ttfb"][api_name])
                        api_ttfb_times[api_name].append(avg_ttfb)
                    else:
                        api_ttfb_times[api_name].append(0)

                    # 总响应平均时间
                    if api_name in bucket["api_total"] and bucket["api_total"][api_name]:
                        avg_total = sum(bucket["api_total"][api_name]) / len(bucket["api_total"][api_name])
                        api_total_times[api_name].append(avg_total)
                    else:
                        api_total_times[api_name].append(0)

            # 数据已经是按时间顺序（旧→新），不需要反转
            # ECharts 从左到右渲染，所以最旧的在左边，最新的在右边

            return {
                "labels": labels,
                "total_requests": total_requests,
                "failed_requests": failed_requests,
                # 新字段：按搜索 API 端点聚合
                "api_requests": dict(api_requests),
                "api_ttfb_times": dict(api_ttfb_times),
                "api_total_times": dict(api_total_times),
            }

        return await asyncio.to_thread(_query)

    async def get_total_counts(self) -> Tuple[int, int]:
        """获取总成功和失败次数"""
        def _query():
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                success = conn.execute(
                    "SELECT COUNT(*) FROM request_logs WHERE status = 'success'"
                ).fetchone()[0]
                failed = conn.execute(
                    "SELECT COUNT(*) FROM request_logs WHERE status != 'success'"
                ).fetchone()[0]
            return success, failed

        return await asyncio.to_thread(_query)

    async def cleanup_old_data(self, days: int = 30):
        """清理过期数据 - 默认保留30天"""
        def _cleanup():
            cutoff_time = int(time.time() - days * 24 * 3600)
            conn = _get_sqlite_conn()
            with _sqlite_lock:
                cursor = conn.execute(
                    "DELETE FROM request_logs WHERE timestamp < ?",
                    (cutoff_time,)
                )
                conn.commit()
                return cursor.rowcount

        return await asyncio.to_thread(_cleanup)


# 全局实例
stats_db = StatsDatabase()
