"""调试2：看一条完整的 advisory 结构"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fetcher import fetch_advisories

raw = fetch_advisories(since_hours=48)
if raw:
    # 看第一条 critical 的完整结构
    for adv in raw:
        if adv.get('severity') == 'critical' and adv.get('type') == 'reviewed':
            print(json.dumps(adv, indent=2, ensure_ascii=False)[:5000])
            break
