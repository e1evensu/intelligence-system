#!/usr/bin/env python3
"""情报系统入口 — GHSA 漏洞情报模块"""
import sys
import os
import json
from datetime import datetime

# 项目根目录加入 path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config import REPORTS_DIR, DATA_DIR, DB_PATH
from modules.ghsa.db import init_db, get_conn
from modules.ghsa.fetcher import fetch_advisories, fetch_commit_diff
from modules.ghsa.curator import curate
from modules.ghsa.analyzer import analyze_vulnerability
from modules.ghsa.renderer import render_report
from modules.ghsa.pusher import upload_to_oss
from modules.ghsa.db import save_advisory, save_daily_report, advisory_exists


def main():
    print("=" * 50)
    print(f"GHSA Intel — {datetime.now().isoformat()}")
    print("=" * 50)

    os.makedirs(DATA_DIR, exist_ok=True)
    init_db()

    # 1. 抓取
    raw = fetch_advisories(since_hours=48)
    total_fetched = len(raw)

    if not raw:
        print("[main] No advisories fetched. Exiting.")
        return

    # 2. 过滤排序
    curated = curate(raw)

    if not curated:
        print("[main] No advisories passed filtering.")
        return

    # 3. 去重
    new_items = [item for item in curated if not advisory_exists(item['ghsa_id'])]
    print(f"[main] {len(curated)} curated, {len(new_items)} new")

    if not new_items:
        print("[main] All already in DB. Generating report from DB data.")
        conn = get_conn()
        rows = conn.execute("SELECT * FROM advisories ORDER BY cvss_score DESC").fetchall()
        conn.close()
        analyzed = [dict(r) for r in rows]
    else:
        # 4. AI 分析，逐条存 DB
        analyzed = []
        for i, item in enumerate(new_items):
            label = item.get('cve_id') or item.get('ghsa_id')
            print(f"[analyzer] {i+1}/{len(new_items)}: {label}")

            # 尝试获取 commit diff
            commit_diff = ''
            refs = item.get('references', [])
            for ref in (refs or []):
                url = ref if isinstance(ref, str) else ref.get('url', '')
                if 'commit' in url:
                    print(f"[fetcher] Fetching commit diff: {url}")
                    commit_diff = fetch_commit_diff(url)
                    if commit_diff:
                        break

            item['raw_references'] = json.dumps(refs, ensure_ascii=False) if refs else ''

            analyzed_item = analyze_vulnerability(item, commit_diff=commit_diff)
            save_advisory(analyzed_item)
            analyzed.append(analyzed_item)

    # 5. 生成日报
    today = datetime.now().strftime('%Y-%m-%d')
    html = render_report(analyzed, today, total_fetched)

    os.makedirs(os.path.join(REPORTS_DIR, today), exist_ok=True)
    html_path = os.path.join(REPORTS_DIR, today, 'index.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[main] Report saved: {html_path}")

    # 6. 上传 OSS（路径不带 index.html）
    oss_url = upload_to_oss(html_path, f'ghsa-daily/{today}')

    # 7. 存日报记录
    urgent = sum(1 for i in analyzed if i.get('urgency') == '🔴紧急')
    high = sum(1 for i in analyzed if i.get('urgency') == '🟠高危')
    watch = sum(1 for i in analyzed if i.get('urgency') == '🟡关注')
    save_daily_report(today, total_fetched, len(analyzed), urgent, high, watch, html_path, oss_url)

    # 8. 输出
    print()
    print("=" * 50)
    print(f"日报: {today}")
    print(f"抓取: {total_fetched} | 入选: {len(analyzed)}")
    print(f"🔴紧急: {urgent} | 🟠高危: {high} | 🟡关注: {watch}")
    if oss_url:
        print(f"链接: {oss_url}")
    print("=" * 50)

    if oss_url:
        print(f"\nOSS_URL={oss_url}")


if __name__ == '__main__':
    main()
