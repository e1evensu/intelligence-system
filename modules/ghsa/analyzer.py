"""Analyzer: 用 SiliconFlow API 做深度中文漏洞分析"""
import json
import httpx
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from config import SILICONFLOW_API_KEY, SILICONFLOW_API_BASE, SILICONFLOW_MODEL

def analyze_vulnerability(item: dict, commit_diff: str = '') -> dict:
    """调用 SiliconFlow API 深度分析单条漏洞"""
    
    # Build references context
    refs = item.get('references', []) or []
    refs_text = ''
    if refs:
        ref_urls = []
        for r in refs:
            url = r if isinstance(r, str) else r.get('url', '')
            if url:
                ref_urls.append(url)
        refs_text = '\n'.join(ref_urls[:10])

    # Build diff context
    diff_section = ''
    if commit_diff:
        diff_section = f"""
## 修复 Commit Diff
```
{commit_diff[:2000]}
```
"""

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
{item.get('description', '') or item.get('summary', '')[:800]}

## 参考链接
{refs_text}
{diff_section}
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
    "source": "用户输入从哪里进入系统（如 WebSocket message body / HTTP parameter / 文件上传）",
    "propagation": "数据如何从 source 流转到 sink，经过哪些函数/类/方法",
    "sink": "最终的危险操作（如 pickle.loads() / eval() / os.system() / SQL query）",
    "chain": "完整调用链，如：WebSocket.recv() -> FrameSerializer.deserialize() -> pickle.loads(data)"
  }}}},
  "poc": {{{{
    "description": "最小 PoC 概念验证描述",
    "raw_request": "完整的 raw HTTP request（见下方规则）"
  }}}},
  "fix_analysis": {{{{
    "before_code": "漏洞代码片段（从描述或 diff 中提取的漏洞代码，必须包含函数名和关键行）",
    "after_code": "修复后的代码片段（从 diff 中提取，或从描述推断的修复代码）",
    "fix_principle": "修复的核心原理：为什么这个改动能堵住漏洞，从安全工程角度解释（不是写建议，是写原理）",
    "upgrade_to": "升级到什么版本"
  }}}}
}}}}

## ⚠️ 关键规则

### fix_analysis 规则（最重要）
1. **before_code**：必须从漏洞描述或 diff 中提取具体的漏洞代码片段。description 里通常会提到文件路径和函数名，把相关代码摘出来。如果 description 里有代码块，直接用
2. **after_code**：如果有 diff，从 diff 中提取修复后的代码。如果没有 diff，基于 description 中提到的修复方式推断修复代码
3. **fix_principle**：不是写"建议升级到X版本"，而是解释修复的技术原理。例如："将 pickle.loads() 替换为 json.loads()，因为 JSON 是安全的数据格式不支持代码执行" 或 "在调用 os.system() 前用 shlex.quote() 转义参数，阻断 shell 元字符注入"
4. **绝不允许**只写"升级到 vX.Y.Z"就完事，必须给出代码层面的分析

### poc 规则（严格）
1. **raw_request 必须是完整的 HTTP/WebSocket request**，格式如下：
```
POST /path HTTP/1.1
Host: target:port
Header: value

body
```
2. **对于库级别漏洞**（如 xmldom、pipecat、zserio），构造一个假设目标服务使用了该库的最简 HTTP 请求场景。例如 xmldom 漏洞，假设有个 Node.js Web 服务接收 XML body 用 xmldom 解析，则 raw_request 就是带恶意 XML 的 POST 请求
3. **对于非 HTTP 协议漏洞**（如 Bolt 二进制协议），给出等效的 TCP payload 或该协议的原生请求格式
4. payload 必须完整、可直接复制到 Burp Suite 发送，不要用 "...(省略)" 这种写法

### 其他规则
- 严禁编造：所有分析必须基于提供的漏洞描述和 diff
- urgency：CVSS≥9.0 或远程无认证可利用 → 🔴紧急；CVSS 7.0-8.9 → 🟠高危
- sink_source 必须给具体函数名和调用路径
- 输出纯 JSON，不要用 ```json``` 包裹"""

    try:
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
            print(f"[analyzer] API error {resp.status_code}: {resp.text[:200]}")
            return _fallback_analysis(item)
        
        data = resp.json()
        content = data['choices'][0]['message']['content'].strip()
        
        # 去掉可能的 markdown 代码块包裹
        if content.startswith('```'):
            content = content.split('\n', 1)[1] if '\n' in content else content[3:]
        if content.endswith('```'):
            content = content[:-3]
        content = content.strip()
        
        analysis = json.loads(content)
        
        # Extract nested fields
        sink_source_raw = analysis.get('sink_source', {})
        poc_raw = analysis.get('poc', {})
        fix_raw = analysis.get('fix_analysis', {})
        
        # Store raw JSON for renderer
        item.update({
            'vuln_type': analysis.get('vuln_type', ''),
            'affected': item.get('affected', ''),
            'exploit_difficulty': analysis.get('exploit_difficulty', ''),
            'urgency': analysis.get('urgency', '🟡关注'),
            'summary_cn': analysis.get('summary_cn', item.get('summary', '')),
            'action': analysis.get('action', ''),
            'business_context': analysis.get('business_context', ''),
            'sink_source': json.dumps(sink_source_raw, ensure_ascii=False) if isinstance(sink_source_raw, dict) else str(sink_source_raw),
            'poc': json.dumps(poc_raw, ensure_ascii=False) if isinstance(poc_raw, dict) else str(poc_raw),
            'fix_detail': json.dumps(fix_raw, ensure_ascii=False) if isinstance(fix_raw, dict) else str(fix_raw),
            '_sink_source_parsed': sink_source_raw,
            '_poc_parsed': poc_raw,
            '_fix_parsed': fix_raw,
        })
        
    except json.JSONDecodeError as e:
        print(f"[analyzer] JSON parse error: {e}")
        return _fallback_analysis(item)
    except Exception as e:
        print(f"[analyzer] Error: {e}")
        return _fallback_analysis(item)
    
    return item

def _fallback_analysis(item: dict) -> dict:
    """AI 分析失败时的兜底逻辑"""
    cvss = item.get('cvss_score', 0)
    if cvss >= 9.0:
        urgency = '🔴紧急'
    elif cvss >= 7.0:
        urgency = '🟠高危'
    else:
        urgency = '🟡关注'
    
    default_sink = {"source": "信息不足", "propagation": "信息不足", "sink": "信息不足", "chain": "信息不足"}
    default_poc = {"description": "信息不足", "raw_request": "信息不足"}
    default_fix = {"before_code": "信息不足", "after_code": "信息不足", "fix_principle": "信息不足", "upgrade_to": item.get('patched_version', '未知')}
    
    item.update({
        'vuln_type': item.get('summary', '')[:50],
        'affected': '',
        'exploit_difficulty': '未知',
        'urgency': urgency,
        'summary_cn': item.get('summary', ''),
        'action': '关注官方更新',
        'business_context': '信息不足',
        'sink_source': json.dumps(default_sink, ensure_ascii=False),
        'poc': json.dumps(default_poc, ensure_ascii=False),
        'fix_detail': json.dumps(default_fix, ensure_ascii=False),
        '_sink_source_parsed': default_sink,
        '_poc_parsed': default_poc,
        '_fix_parsed': default_fix,
    })
    return item
