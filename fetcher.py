"""Fetcher: 从 GHSA REST API 抓取高危 advisory"""
import re
import httpx
from datetime import datetime, timedelta, timezone
from config import GH_API_BASE, GITHUB_TOKEN, HOURS_WINDOW, MIN_SEVERITY

HEADERS = {
    'Accept': 'application/vnd.github+json',
    'Authorization': f'Bearer {GITHUB_TOKEN}',
    'X-GitHub-Api-Version': '2022-11-28',
}

def fetch_advisories(since_hours: int = HOURS_WINDOW) -> list:
    """抓取最近的高危 advisory"""
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    all_advisories = []
    page = 1
    
    for severity in MIN_SEVERITY:
        per_page = 100
        resp = httpx.get(
            f'{GH_API_BASE}/advisories',
            params={
                'type': 'reviewed',
                'severity': severity,
                'per_page': per_page,
                'page': page,
            },
            headers=HEADERS,
            timeout=30,
        )
        
        if resp.status_code != 200:
            print(f"[fetcher] GHSA API error: {resp.status_code} {resp.text[:200]}")
            continue
        
        data = resp.json()
        # 过滤时间窗口
        for adv in data:
            pub_str = adv.get('published_at', '')
            if pub_str:
                pub_dt = datetime.fromisoformat(pub_str.replace('Z', '+00:00'))
                if pub_dt >= since:
                    all_advisories.append(adv)
        
    print(f"[fetcher] Fetched {len(all_advisories)} advisories (severity={MIN_SEVERITY}, window={since_hours}h)")
    return all_advisories


def fetch_commit_diff(commit_url: str) -> str:
    """从 GitHub commit URL 获取 diff 内容。
    
    输入: https://github.com/{owner}/{repo}/commit/{sha}
    输出: files[].patch 拼接的 diff 文本（最多 3000 字符）
    """
    match = re.match(r'https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)', commit_url)
    if not match:
        return ''
    owner, repo, sha = match.group(1), match.group(2), match.group(3)
    
    try:
        resp = httpx.get(
            f'{GH_API_BASE}/repos/{owner}/{repo}/commits/{sha}',
            headers=HEADERS,
            timeout=15,
        )
        if resp.status_code != 200:
            print(f"[fetcher] commit diff API error: {resp.status_code}")
            return ''
        
        data = resp.json()
        files = data.get('files', [])
        patches = []
        for f in files:
            fname = f.get('filename', '')
            patch = f.get('patch', '')
            if patch:
                patches.append(f"--- {fname}\n{patch}")
        
        diff_text = '\n\n'.join(patches)
        # 截断以避免 prompt 过长
        if len(diff_text) > 3000:
            diff_text = diff_text[:3000] + '\n... (truncated)'
        return diff_text
        
    except Exception as e:
        print(f"[fetcher] fetch_commit_diff error: {e}")
        return ''
