"""重新分析6条走fallback的GHSA advisory"""
import sqlite3, json, httpx, os, time
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

SILICONFLOW_API_KEY = os.getenv('SILICONFLOW_API_KEY', '')
SILICONFLOW_API_BASE = os.getenv('SILICONFLOW_API_BASE', 'https://api.siliconflow.cn/v1')
SILICONFLOW_MODEL = os.getenv('SILICONFLOW_MODEL', 'stepfun-ai/Step-3.5-Flash')

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'ghsa_intel.db')

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute("""SELECT ghsa_id, cve_id, summary, severity, published_at, repo, stars, cvss_score,
             description, ecosystem, package_name, patched_version, language, raw_references
             FROM advisories WHERE poc LIKE '%信息不足%'""")
rows = c.fetchall()

col_names = ['ghsa_id','cve_id','summary','severity','published_at','repo','stars','cvss_score',
             'description','ecosystem','package_name','patched_version','language','raw_references']

print(f"Found {len(rows)} advisories to re-analyze")
print(f"Model: {SILICONFLOW_MODEL}")

def build_prompt(item):
    refs_text = ''
    if item.get('raw_references'):
        try:
            refs = json.loads(item['raw_references']) if isinstance(item['raw_references'], str) else item['raw_references']
            ref_urls = [r.get('url','') if isinstance(r,dict) else str(r) for r in (refs or [])][:10]
            refs_text = '\n'.join(ref_urls)
        except:
            refs_text = str(item.get('raw_references',''))[:500]

    desc = item.get('description', '') or item.get('summary', '')
    if desc:
        desc = desc[:800]

    prompt = f"""你是高级安全研究员，专精漏洞分析与攻击面评估。请分析以下安全漏洞。

## 漏洞基础信息
- GHSA ID: {item.get('ghsa_id', '')}
- CVE: {item.get('cve_id', '')}
- 项目: {item.get('repo', '')} (⭐ {item.get('stars', 0)})
- 语言: {item.get('language', '')}
- 生态: {item.get('ecosystem', '')}
- 包名: {item.get('package_name', '')}
- 严重程度: {item.get('severity', '')}
- CVSS: {item.get('cvss_score', 0)}
- 已修复版本: {item.get('patched_version', '未知')}

## 漏洞描述
{desc}

## 参考链接
{refs_text}
---

请严格基于以上信息进行深度分析，输出以下 JSON 格式（纯 JSON，不要 markdown 代码块包裹）：

{{{{
  "vuln_type": "漏洞类型一句话（如：反序列化RCE / SQL注入 / SSRF / 路径穿越 / 认证绕过）",
  "urgency": "🔴紧急 或 🟠高危 或 🟡关注",
  "exploit_difficulty": "高/中/低",
  "summary_cn": "中文摘要 ≤200字，准确描述漏洞本质、攻击面、影响范围",
  "action": "具体建议动作（如：立即升级到 vX.Y.Z / 审查依赖 / 暂无修复）",
  "business_context": "这个项目是做什么业务的，什么业务场景下会触发这个漏洞",
  "sink_source": {{{{
    "source": "用户输入从哪里进入系统",
    "propagation": "数据如何从 source 流转到 sink",
    "sink": "最终的危险操作",
    "chain": "完整调用链"
  }}}},
  "poc": {{{{
    "description": "最小 PoC 概念验证描述",
    "raw_request": "完整的 raw HTTP request（见下方规则）"
  }}}},
  "fix_analysis": {{{{
    "before_code": "漏洞代码片段",
    "after_code": "修复后的代码片段",
    "fix_principle": "修复的核心原理",
    "upgrade_to": "升级到什么版本"
  }}}}
}}}}

## 关键规则
1. poc.raw_request 必须是完整可发送的 HTTP request，库级别漏洞要构造假设部署场景
2. sink_source 必须给具体函数名和调用路径
3. fix_analysis 必须给代码层面分析，不能只写"升级到X版本"
4. 严禁编造：所有分析必须基于提供的漏洞描述
5. 输出纯 JSON，不要用 ```json``` 包裹"""

    return prompt

def call_api(prompt):
    resp = httpx.post(
        f'{SILICONFLOW_API_BASE}/chat/completions',
        headers={
            'Authorization': f'Bearer {SILICONFLOW_API_KEY}',
            'Content-Type': 'application/json',
        },
        json={
            'model': SILICONFLOW_MODEL,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.3,
        },
        timeout=180,
    )
    if resp.status_code != 200:
        print(f"  API error {resp.status_code}: {resp.text[:300]}")
        return None
    data = resp.json()
    content = data['choices'][0]['message']['content'].strip()
    if content.startswith('```'):
        content = content.split('\n', 1)[1] if '\n' in content else content[3:]
    if content.endswith('```'):
        content = content[:-3]
    return json.loads(content.strip())

success = 0
failed = 0

for i, row in enumerate(rows):
    item = dict(zip(col_names, row))
    ghsa_id = item['ghsa_id']
    print(f"\n[{i+1}/{len(rows)}] Analyzing {ghsa_id} ({item['severity']}, {item['repo']})...")
    
    prompt = build_prompt(item)
    try:
        analysis = call_api(prompt)
        if not analysis:
            failed += 1
            continue
        
        sink_source_raw = analysis.get('sink_source', {})
        poc_raw = analysis.get('poc', {})
        fix_raw = analysis.get('fix_analysis', {})
        
        c.execute("""UPDATE advisories SET 
            vuln_type=?, urgency=?, exploit_difficulty=?, summary_cn=?, action=?,
            business_context=?, sink_source=?, poc=?, fix_detail=?, analyzed_at=datetime('now')
            WHERE ghsa_id=?""",
            (
                analysis.get('vuln_type', ''),
                analysis.get('urgency', '🟡关注'),
                analysis.get('exploit_difficulty', ''),
                analysis.get('summary_cn', ''),
                analysis.get('action', ''),
                analysis.get('business_context', ''),
                json.dumps(sink_source_raw, ensure_ascii=False),
                json.dumps(poc_raw, ensure_ascii=False),
                json.dumps(fix_raw, ensure_ascii=False),
                ghsa_id,
            ))
        conn.commit()
        print(f"  ✓ Updated successfully")
        print(f"    vuln_type: {analysis.get('vuln_type','')}")
        poc_desc = str(analysis.get('poc',{}).get('description',''))[:80]
        print(f"    poc desc: {poc_desc}")
        success += 1
    except json.JSONDecodeError as e:
        print(f"  ✗ JSON parse error: {e}")
        failed += 1
    except Exception as e:
        print(f"  ✗ Failed: {type(e).__name__}: {e}")
        failed += 1
    
    # Rate limit protection
    if i < len(rows) - 1:
        time.sleep(2)

conn.close()
print(f"\n=== DONE: {success} success, {failed} failed ===")
