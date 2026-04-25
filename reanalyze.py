#!/usr/bin/env python3
"""补分析 fallback 条目"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import get_conn, save_advisory
from fetcher import fetch_commit_diff
from analyzer import analyze_vulnerability

conn = get_conn()
rows = conn.execute("SELECT ghsa_id FROM advisories WHERE fix_detail LIKE '%信息不足%' OR fix_detail = ''").fetchall()
fallback_ids = [r[0] for r in rows]
conn.close()

print(f"Fallback items to re-analyze: {len(fallback_ids)}")

# 从原始数据重新获取这些条目
from fetcher import fetch_advisories
from curator import curate

raw = fetch_advisories(since_hours=72)
curated = curate(raw)

to_reanalyze = [item for item in curated if item['ghsa_id'] in fallback_ids]
print(f"Found {len(to_reanalyze)} items to re-analyze\n")

for i, item in enumerate(to_reanalyze):
    label = item.get('cve_id') or item.get('ghsa_id')
    print(f"[re-analyze] {i+1}/{len(to_reanalyze)}: {label}")
    
    # fetch commit diff
    commit_diff = ''
    refs = item.get('references', [])
    for ref in (refs or []):
        url = ref if isinstance(ref, str) else ref.get('url', '')
        if 'commit' in url:
            commit_diff = fetch_commit_diff(url)
            if commit_diff:
                break
    
    item['raw_references'] = json.dumps(refs, ensure_ascii=False) if refs else ''
    analyzed = analyze_vulnerability(item, commit_diff=commit_diff)
    save_advisory(analyzed)
    print(f"  -> done, urgency={analyzed.get('urgency','?')}")

print(f"\nRe-analyzed {len(to_reanalyze)} items")
