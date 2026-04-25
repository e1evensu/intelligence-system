"""Curator: 严格过滤 + enrichment"""
import re
import json
import httpx
from datetime import datetime, timedelta, timezone
from config import (HOURS_WINDOW, GH_API_BASE, GITHUB_TOKEN,
                    SILICONFLOW_API_KEY, SILICONFLOW_API_BASE, SILICONFLOW_MODEL)

HEADERS = {
    'Accept': 'application/vnd.github+json',
    'Authorization': f'Bearer {GITHUB_TOKEN}',
    'X-GitHub-Api-Version': '2022-11-28',
}

def extract_cve(identifiers: list) -> str:
    for ident in (identifiers or []):
        if ident.get('type') == 'CVE':
            return ident.get('value', '')
    return ''

def extract_cvss(cvss: dict) -> float:
    score = 0.0
    for version in ['cvss_v4', 'cvss_v3']:
        v = cvss.get(version, {})
        if v and v.get('score') and v['score'] > score:
            score = v['score']
    return score

def extract_repo(vulns: list) -> str:
    for v in (vulns or []):
        pkg = v.get('package', {})
        ecosystem = (pkg.get('ecosystem') or '').lower()
        name = pkg.get('name', '')
        if not name:
            continue
        repo_obj = pkg.get('repository')
        if repo_obj and isinstance(repo_obj, dict):
            url = repo_obj.get('url', '')
            if 'github.com' in url:
                parts = url.rstrip('/').split('github.com/')
                if len(parts) > 1:
                    segments = parts[1].rstrip('.git').split('/')
                    if len(segments) >= 2:
                        return f"{segments[0]}/{segments[1]}"
        if ecosystem == 'go' and 'github.com/' in name:
            match = re.match(r'github\.com/([^/]+)/([^/]+)', name)
            if match:
                return f"{match.group(1)}/{match.group(2)}"
    return ''

def search_github_repo(package_name: str, ecosystem: str) -> str:
    try:
        resp = httpx.get(
            f'{GH_API_BASE}/search/repositories',
            params={'q': f'{package_name} in:name', 'per_page': 3},
            headers=HEADERS, timeout=10,
        )
        if resp.status_code == 200:
            items = resp.json().get('items', [])
            if items:
                return items[0]['full_name']
    except Exception:
        pass
    return ''

def get_repo_info(repo: str) -> dict:
    if not repo:
        return {'stars': 0, 'language': ''}
    try:
        resp = httpx.get(f'{GH_API_BASE}/repos/{repo}', headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {'stars': data.get('stargazers_count', 0), 'language': data.get('language', '')}
    except Exception:
        pass
    return {'stars': 0, 'language': ''}

def has_fix_reference(references: list) -> bool:
    ref_list = references or []
    if len(ref_list) == 0:
        return False
    for ref in ref_list:
        url = ref if isinstance(ref, str) else ref.get('url', '')
        if any(kw in url for kw in ('commit', 'pull', 'release', 'patch', 'security/advisories')):
            return True
    return True

def ai_filter_exploitable(items: list) -> list:
    """用 AI 批量判断哪些漏洞是可利用的（排除纯 DoS/OOM/崩溃）"""
    if not items:
        return items
    
    entries = []
    for i, item in enumerate(items):
        summary = item.get('summary', '')
        desc = (item.get('description', '') or '')[:300]
        entries.append(f"{i}. [{item.get('severity','')}] {summary}\n   {desc}")
    
    entries_text = '\n'.join(entries)
    
    prompt = f"""你是安全研究员。以下是安全漏洞列表，请判断每条是否是"可利用的高危漏洞"。

可利用的（保留）：RCE、命令/代码注入、SQL注入、反序列化、SSRF、认证/权限/签名绕过、路径穿越、SSTI、权限提升、数据窃取、XML注入/XXE、XSS
排除的（不要）：纯DoS/OOM/崩溃/panic、纯内存耗尽、纯ReDoS/递归爆炸、不可利用的整数溢出

漏洞列表：
{entries_text}

输出纯JSON数组，只包含保留的编号（0起）。例：[0, 2, 5, 7]
不要输出其他内容。"""

    try:
        resp = httpx.post(
            f'{SILICONFLOW_API_BASE}/chat/completions',
            headers={'Authorization': f'Bearer {SILICONFLOW_API_KEY}', 'Content-Type': 'application/json'},
            json={'model': SILICONFLOW_MODEL, 'messages': [{'role': 'user', 'content': prompt}], 'temperature': 0.1},
            timeout=90,
        )
        
        if resp.status_code != 200:
            print(f"[curator] AI filter error {resp.status_code}, keeping all")
            return items
        
        content = resp.json()['choices'][0]['message']['content'].strip()
        if content.startswith('```'):
            content = content.split('\n', 1)[1] if '\n' in content else content[3:]
        if content.endswith('```'):
            content = content[:-3]
        content = content.strip()
        
        keep_indices = json.loads(content)
        filtered = [items[i] for i in keep_indices if 0 <= i < len(items)]
        print(f"[curator] AI filter: {len(items)} -> {len(filtered)} (removed {len(items)-len(filtered)} non-exploitable)")
        return filtered
        
    except Exception as e:
        print(f"[curator] AI filter error: {e}, keeping all")
        return items


def curate(advisories: list) -> list:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=HOURS_WINDOW)
    results = []
    
    for adv in advisories:
        if adv.get('type') != 'reviewed':
            continue
        cve_id = extract_cve(adv.get('identifiers', []))
        severity = (adv.get('severity') or '').lower()
        if not cve_id and severity != 'critical':
            continue
        if severity not in ('high', 'critical'):
            continue
        pub_str = adv.get('published_at', '')
        if pub_str:
            pub_dt = datetime.fromisoformat(pub_str.replace('Z', '+00:00'))
            if pub_dt < cutoff:
                continue
        vulns = adv.get('vulnerabilities', [])
        if not vulns:
            continue
        
        repo = extract_repo(vulns)
        ecosystem = ''
        package_name = ''
        if not repo and vulns:
            pkg = vulns[0].get('package', {})
            ecosystem = (pkg.get('ecosystem') or '').lower()
            package_name = pkg.get('name', '')
            if package_name and severity == 'critical':
                repo = search_github_repo(package_name, ecosystem)
        if not repo:
            desc = adv.get('description', '') or adv.get('summary', '')
            match = re.search(r'github\.com/([^/\s)]+)/([^/\s)]+)', desc)
            if match:
                repo = f"{match.group(1)}/{match.group(2)}"
        
        cvss_score = extract_cvss(adv.get('cvss_severities', {}))
        if not has_fix_reference(adv.get('references', [])):
            continue
        if vulns:
            pkg = vulns[0].get('package', {})
            ecosystem = ecosystem or (pkg.get('ecosystem') or '')
            package_name = package_name or pkg.get('name', '')
        patched = ''
        for v in vulns:
            fpv = v.get('first_patched_version')
            if fpv:
                patched = fpv
                break
        
        results.append({
            'ghsa_id': adv.get('ghsa_id', ''), 'cve_id': cve_id,
            'summary': adv.get('summary', ''), 'description': adv.get('description', ''),
            'severity': severity, 'cvss_score': cvss_score, 'published_at': pub_str,
            'repo': repo, 'ecosystem': ecosystem, 'package_name': package_name,
            'patched_version': patched, 'references': adv.get('references', []),
            'ghsa_url': adv.get('html_url', ''),
        })
    
    # AI 批量过滤
    results = ai_filter_exploitable(results)
    
    # Enrichment
    for item in results:
        if item['repo']:
            info = get_repo_info(item['repo'])
            item['stars'] = info.get('stars', 0)
            item['language'] = info.get('language', '')
        else:
            item['stars'] = 0
            item['language'] = ''
    
    # Star 过滤
    filtered = []
    for r in results:
        if r['repo']:
            if r.get('stars', 0) >= 100:
                filtered.append(r)
            elif r['severity'] == 'critical' and r.get('patched_version'):
                filtered.append(r)
        elif r['severity'] == 'critical':
            filtered.append(r)
    
    filtered.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
    print(f"[curator] {len(advisories)} -> {len(filtered)} after all filtering")
    return filtered
