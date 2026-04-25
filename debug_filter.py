"""调试：看看 38 条 advisory 为什么被过滤"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fetcher import fetch_advisories
from curator import extract_cve, extract_repo, extract_cvss, has_fix_reference

raw = fetch_advisories(since_hours=48)

print(f"\nTotal: {len(raw)}\n")

reasons = {'no_cve': 0, 'wrong_severity': 0, 'no_vulns': 0, 'no_repo': 0, 'low_stars': 0, 'type_wrong': 0, 'pass': 0}

for adv in raw:
    ghsa = adv.get('ghsa_id', '')
    sev = adv.get('severity', '')
    typ = adv.get('type', '')
    cve = extract_cve(adv.get('identifiers', []))
    vulns = adv.get('vulnerabilities', [])
    repo = extract_repo(vulns)
    cvss = extract_cvss(adv.get('cvss_severities', {}))
    refs = adv.get('references', [])
    
    issues = []
    if typ != 'reviewed':
        issues.append(f'type={typ}')
        reasons['type_wrong'] += 1
    if not cve:
        issues.append('no_cve')
        reasons['no_cve'] += 1
    if not vulns:
        issues.append('no_vulns')
        reasons['no_vulns'] += 1
    if not repo:
        issues.append('no_repo')
        reasons['no_repo'] += 1
    
    print(f"{ghsa} | sev={sev} type={typ} cve={cve} vulns={len(vulns)} repo={repo} cvss={cvss}")
    if issues:
        print(f"  ❌ {', '.join(issues)}")
    else:
        print(f"  ✅ pass (need to check stars)")
        reasons['pass'] += 1

print(f"\nFilter reasons: {reasons}")
