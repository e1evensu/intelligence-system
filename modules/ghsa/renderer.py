"""Renderer: 深色主题 HTML 日报 — 深度漏洞分析版"""
import json
from collections import Counter

def render_report(items: list, date: str, total_fetched: int) -> str:
    """生成 HTML 日报"""
    
    # --- 统计数据 ---
    urgent = [i for i in items if i.get('urgency') == '🔴紧急']
    high = [i for i in items if i.get('urgency') == '🟠高危']
    watch = [i for i in items if i.get('urgency') == '🟡关注']
    
    # Ecosystem 分布
    eco_counter = Counter()
    for i in items:
        eco = (i.get('ecosystem') or 'unknown').lower()
        # Normalize
        eco_map = {
            'pip': 'pip', 'pypi': 'pip',
            'npm': 'npm',
            'go': 'Go',
            'maven': 'Maven',
            'nuget': 'NuGet',
            'composer': 'Composer',
            'rubygems': 'RubyGems',
            'cargo': 'Cargo',
            'pub': 'Pub',
        }
        eco_label = eco_map.get(eco, eco.capitalize() if eco != 'unknown' else 'Other')
        eco_counter[eco_label] += 1
    
    # Vuln type 分布
    vuln_counter = Counter()
    for i in items:
        vt = i.get('vuln_type', '未分类')
        # Truncate long types
        if len(vt) > 20:
            vt = vt[:18] + '...'
        vuln_counter[vt] += 1
    
    # --- Chart data ---
    eco_labels = json.dumps(list(eco_counter.keys()), ensure_ascii=False)
    eco_values = json.dumps(list(eco_counter.values()))
    eco_colors = json.dumps(_chart_colors(len(eco_counter)))
    
    vuln_labels = json.dumps(list(vuln_counter.keys()), ensure_ascii=False)
    vuln_values = json.dumps(list(vuln_counter.values()))
    vuln_colors = json.dumps(_chart_colors(len(vuln_counter)))
    
    # --- Build cards HTML ---
    cards_html = ''
    for item in items:
        cards_html += _render_card(item)
    
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全漏洞日报 — {date}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ 
  font-family: -apple-system, 'SF Pro', 'PingFang SC', 'Helvetica Neue', Arial, sans-serif;
  background: #0a0a0f; color: #e0e0e6; 
  line-height: 1.7; padding: 20px;
}}
.container {{ max-width: 860px; margin: 0 auto; }}
h1 {{ font-size: 24px; font-weight: 700; color: #fff; margin-bottom: 4px; }}
.subtitle {{ font-size: 13px; color: #777; margin-bottom: 28px; }}

/* Charts section */
.charts-row {{
  display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
  margin-bottom: 28px;
}}
.chart-box {{
  background: #111118; border: 1px solid #1e1e2e; border-radius: 10px;
  padding: 16px;
}}
.chart-title {{ font-size: 13px; font-weight: 600; color: #999; margin-bottom: 10px; }}
.chart-container {{ position: relative; height: 220px; }}

/* Section titles */
.section-title {{ 
  font-size: 15px; font-weight: 700; 
  margin: 28px 0 14px; padding-bottom: 8px;
  border-bottom: 1px solid #1e1e2e;
}}

/* Card */
.card {{
  background: #111118; border: 1px solid #1e1e2e; border-radius: 10px;
  padding: 20px; margin-bottom: 16px;
  border-left: 3px solid #333;
}}
.card.urgent {{ border-left-color: #ef4444; }}
.card.high {{ border-left-color: #f97316; }}
.card.watch {{ border-left-color: #eab308; }}

.card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }}
.card-title {{ font-size: 16px; font-weight: 700; color: #fff; }}
.card-meta {{ font-size: 12px; color: #777; display: flex; gap: 14px; flex-wrap: wrap; margin-top: 4px; }}
.card-meta span {{ white-space: nowrap; }}
.badge {{
  display: inline-block; font-size: 11px; font-weight: 700; 
  padding: 2px 10px; border-radius: 5px;
}}
.badge-critical {{ background: #dc262625; color: #f87171; border: 1px solid #dc262640; }}
.badge-high {{ background: #ea580c25; color: #fb923c; border: 1px solid #ea580c40; }}
.badge-medium {{ background: #eab30825; color: #fbbf24; border: 1px solid #eab30840; }}

/* Card sections */
.card-section {{ margin-top: 14px; }}
.section-label {{ 
  font-size: 12px; font-weight: 700; color: #555; 
  margin-bottom: 4px; letter-spacing: 0.5px;
}}
.section-content {{ font-size: 13px; color: #bbb; }}

/* Attack chain */
.attack-chain {{ 
  background: #0d0d14; border: 1px solid #1a1a28; border-radius: 8px;
  padding: 12px 14px; margin-top: 4px;
}}
.chain-step {{ 
  display: flex; align-items: flex-start; gap: 10px;
  padding: 4px 0;
}}
.chain-step .label {{ 
  font-size: 11px; font-weight: 700; color: #7dd3fc;
  min-width: 90px; text-align: right; flex-shrink: 0;
  padding-top: 1px;
}}
.chain-step .value {{ font-size: 12px; color: #ccc; word-break: break-all; }}
.chain-arrow {{ 
  text-align: center; color: #444; font-size: 14px; 
  margin: 2px 0 2px 45px;
}}

/* PoC code block */
.poc-block {{
  background: #0d0d14; border: 1px solid #1a1a28; border-radius: 8px;
  padding: 12px 14px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 12px; color: #a8d8a8; white-space: pre-wrap; word-break: break-all;
  margin-top: 4px;
}}

/* Fix section */
.fix-section {{ margin-top: 4px; }}
.fix-label {{ font-size: 11px; font-weight: 600; color: #888; margin-top: 8px; margin-bottom: 4px; }}
.fix-version {{ font-size: 11px; color: #7dd3fc; margin-top: 8px; padding-top: 6px; border-top: 1px solid #1a1a28; }}
.code-block {{
  background: #0d0d14; border: 1px solid #1a1a28; border-radius: 8px;
  padding: 10px 12px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 11px; color: #f87171; white-space: pre-wrap; word-break: break-all;
  margin: 0 0 4px 0; overflow-x: auto;
}}
.code-block.fix-code {{ color: #4ade80; border-color: #1a3a1a; }}

/* Links */
a {{ color: #7dd3fc; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.link-row {{ margin-top: 12px; display: flex; gap: 16px; font-size: 12px; }}

/* Stats */
.stats {{
  background: #111118; border: 1px solid #1e1e2e; border-radius: 10px;
  padding: 18px; margin-top: 32px;
}}
.stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 14px; }}
.stat-box {{ text-align: center; }}
.stat-value {{ font-size: 28px; font-weight: 800; color: #fff; }}
.stat-label {{ font-size: 11px; color: #777; }}

.empty {{ text-align: center; color: #555; padding: 40px; font-size: 14px; }}

@media (max-width: 640px) {{
  .charts-row {{ grid-template-columns: 1fr; }}
  .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
}}
</style>
</head>
<body>
<div class="container">
  <h1>🔒 安全漏洞深度分析日报</h1>
  <div class="subtitle">{date} · 共 {len(items)} 条 · 抓取 {total_fetched} 条</div>

  <!-- 顶部统计图表 -->
  <div class="charts-row">
    <div class="chart-box">
      <div class="chart-title">📦 生态分布</div>
      <div class="chart-container"><canvas id="ecoChart"></canvas></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">🎯 漏洞类型分布</div>
      <div class="chart-container"><canvas id="vulnChart"></canvas></div>
    </div>
  </div>

  <!-- 漏洞卡片 -->
  {cards_html if cards_html else '<div class="empty">今日无新增高危漏洞</div>'}

  <!-- 底部统计 -->
  <div class="stats">
    <div style="font-size:13px;color:#777;font-weight:600;">📊 今日统计</div>
    <div class="stats-grid">
      <div class="stat-box"><div class="stat-value">{total_fetched}</div><div class="stat-label">抓取</div></div>
      <div class="stat-box"><div class="stat-value">{len(items)}</div><div class="stat-label">入选</div></div>
      <div class="stat-box"><div class="stat-value" style="color:#ef4444;">{len(urgent)}</div><div class="stat-label">🔴 紧急</div></div>
      <div class="stat-box"><div class="stat-value" style="color:#f97316;">{len(high)}</div><div class="stat-label">🟠 高危</div></div>
    </div>
  </div>

  <div style="text-align:center;color:#444;font-size:11px;margin-top:32px;">
    Powered by GHSA Intel · 数据来源 GitHub Security Advisories
  </div>
</div>

<script>
// Ecosystem pie chart
new Chart(document.getElementById('ecoChart'), {{
  type: 'doughnut',
  data: {{
    labels: {eco_labels},
    datasets: [{{ data: {eco_values}, backgroundColor: {eco_colors}, borderColor: '#111118', borderWidth: 2 }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{
      legend: {{ position: 'right', labels: {{ color: '#888', font: {{ size: 11 }}, padding: 8 }} }}
    }}
  }}
}});

// Vuln type bar chart
new Chart(document.getElementById('vulnChart'), {{
  type: 'bar',
  data: {{
    labels: {vuln_labels},
    datasets: [{{ data: {vuln_values}, backgroundColor: {vuln_colors}, borderRadius: 4, barThickness: 18 }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    indexAxis: 'y',
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#666', stepSize: 1 }}, grid: {{ color: '#1a1a28' }} }},
      y: {{ ticks: {{ color: '#999', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
    }}
  }}
}});
</script>
</body>
</html>"""


def _render_card(item: dict) -> str:
    """渲染单条漏洞卡片"""
    urgency = item.get('urgency', '🟡关注')
    if '🔴' in urgency:
        card_class = 'urgent'
        badge_class = 'badge-critical'
    elif '🟠' in urgency:
        card_class = 'high'
        badge_class = 'badge-high'
    else:
        card_class = 'watch'
        badge_class = 'badge-medium'

    cve = item.get('cve_id') or item.get('ghsa_id', '')
    severity = item.get('severity', '').upper()
    cvss = item.get('cvss_score', 0)
    repo = item.get('repo', '')
    stars = item.get('stars', 0)
    eco = item.get('ecosystem', '')
    lang = item.get('language', '')
    
    # Parse sink_source
    sink_source = _parse_json_field(item.get('sink_source', '{}'))
    if not isinstance(sink_source, dict):
        sink_source = {}
    
    # Parse poc
    poc = _parse_json_field(item.get('poc', '{}'))
    if not isinstance(poc, dict):
        poc = {}
    
    # Parse fix_analysis
    fix = _parse_json_field(item.get('fix_detail', '{}'))
    if not isinstance(fix, dict):
        fix = {}
    
    # Also check _parsed versions from analyzer
    if '_sink_source_parsed' in item:
        sink_source = item['_sink_source_parsed']
    if '_poc_parsed' in item:
        poc = item['_poc_parsed']
    if '_fix_parsed' in item:
        fix = item['_fix_parsed']

    business_context = item.get('business_context', '')
    summary_cn = item.get('summary_cn', '')
    action = item.get('action', '')
    exploit_diff = item.get('exploit_difficulty', '')
    
    # References
    refs = item.get('references', [])
    if isinstance(refs, str):
        try:
            refs = json.loads(refs)
        except:
            refs = []
    
    ghsa_url = item.get('ghsa_url', '')
    # Find patch/commit URL from references
    patch_url = ''
    for r in (refs or []):
        url = r if isinstance(r, str) else r.get('url', '')
        if 'commit' in url or 'pull' in url:
            patch_url = url
            break
    
    # Star display
    star_str = ''
    if stars >= 1000:
        star_str = f"{stars // 1000}k"
    elif stars > 0:
        star_str = str(stars)
    
    # Build meta line
    meta_parts = []
    if repo:
        repo_display = repo
        if star_str:
            repo_display += f" (⭐ {star_str})"
        meta_parts.append(f'<span>📦 {repo_display}</span>')
    if eco:
        meta_parts.append(f'<span>🧩 {eco}</span>')
    if lang:
        meta_parts.append(f'<span>🔧 {lang}</span>')
    if exploit_diff:
        meta_parts.append(f'<span>⚡ 利用难度: {exploit_diff}</span>')
    
    # --- Attack chain HTML ---
    attack_html = ''
    if sink_source and any(sink_source.get(k) for k in ['source', 'propagation', 'sink', 'chain']):
        steps = []
        if sink_source.get('source') and sink_source['source'] != '信息不足':
            steps.append(f'<div class="chain-step"><span class="label">Source</span><span class="value">{_esc(sink_source["source"])}</span></div>')
        if sink_source.get('propagation') and sink_source['propagation'] != '信息不足':
            if steps:
                steps.append('<div class="chain-arrow">↓</div>')
            steps.append(f'<div class="chain-step"><span class="label">Propagation</span><span class="value">{_esc(sink_source["propagation"])}</span></div>')
        if sink_source.get('sink') and sink_source['sink'] != '信息不足':
            if steps:
                steps.append('<div class="chain-arrow">↓</div>')
            steps.append(f'<div class="chain-step"><span class="label">Sink</span><span class="value">{_esc(sink_source["sink"])}</span></div>')
        
        if steps:
            attack_html = f'''
    <div class="card-section">
      <div class="section-label">🔗 攻击链 (Source → Sink)</div>
      <div class="attack-chain">
        {''.join(steps)}
      </div>
    </div>'''
        elif sink_source.get('chain') and sink_source['chain'] != '信息不足':
            attack_html = f'''
    <div class="card-section">
      <div class="section-label">🔗 攻击链</div>
      <div class="attack-chain">
        <div class="chain-step"><span class="value">{_esc(sink_source['chain'])}</span></div>
      </div>
    </div>'''

    # --- PoC HTML ---
    poc_html = ''
    poc_desc = poc.get('description', '')
    poc_raw = poc.get('raw_request', '')
    if poc_desc and poc_desc != '信息不足':
        poc_content = _esc(poc_desc)
        if poc_raw and poc_raw != '不适用':
            poc_content += f'\n\n{_esc(poc_raw)}'
        poc_html = f'''
    <div class="card-section">
      <div class="section-label">💻 PoC 概念验证</div>
      <div class="poc-block">{poc_content}</div>
    </div>'''

    # --- Fix analysis HTML ---
    fix_html = ''
    before_code = fix.get('before_code', '')
    after_code = fix.get('after_code', '')
    fix_principle = fix.get('fix_principle', '')
    fix_version = fix.get('upgrade_to', '') or item.get('patched_version', '')
    
    # Fallback to old format if new fields missing
    if not before_code and not fix_principle:
        before_code = fix.get('approach', '')
        fix_principle = fix.get('diff_summary', '')
    
    fix_parts = []
    if before_code and before_code not in ('信息不足', '关注官方更新'):
        fix_parts.append(f'''
      <div class="fix-label">❌ 漏洞代码</div>
      <pre class="code-block">{_esc(before_code)}</pre>''')
    if after_code and after_code not in ('信息不足', ''):
        fix_parts.append(f'''
      <div class="fix-label">✅ 修复代码</div>
      <pre class="code-block fix-code">{_esc(after_code)}</pre>''')
    if fix_principle and fix_principle not in ('无 diff 信息', '信息不足', ''):
        fix_parts.append(f'''
      <div class="fix-label">🔑 修复原理</div>
      <div class="section-content">{_esc(fix_principle)}</div>''')
    if fix_version and fix_version != '未知':
        fix_parts.append(f'<div class="fix-version">升级到: {_esc(fix_version)}</div>')
    
    if fix_parts:
        fix_html = f'''
    <div class="card-section">
      <div class="section-label">🔧 修复分析</div>
      <div class="fix-section">
        {''.join(fix_parts)}
      </div>
    </div>'''

    # --- Business context ---
    biz_html = ''
    if business_context and business_context != '信息不足':
        biz_html = f'''
    <div class="card-section">
      <div class="section-label">📋 业务背景</div>
      <div class="section-content">{_esc(business_context)}</div>
    </div>'''

    # --- Links ---
    links_html = ''
    if ghsa_url or patch_url:
        link_parts = []
        if ghsa_url:
            link_parts.append(f'<a href="{_esc(ghsa_url)}" target="_blank">查看详情 →</a>')
        if patch_url:
            link_parts.append(f'<a href="{_esc(patch_url)}" target="_blank">查看补丁 →</a>')
        links_html = f'<div class="link-row">{"".join(link_parts)}</div>'

    return f'''
  <div class="card {card_class}">
    <div class="card-header">
      <div class="card-title">{_esc(cve)}</div>
      <span class="badge {badge_class}">{urgency} {_esc(severity)} {f'CVSS {cvss}' if cvss else ''}</span>
    </div>
    <div class="card-meta">{''.join(meta_parts)}</div>
    {f'<div class="card-section"><div class="section-content">{_esc(summary_cn)}</div></div>' if summary_cn else ''}
    {biz_html}
    {attack_html}
    {poc_html}
    {fix_html}
    {f'<div class="card-section"><div class="action" style="color:#7dd3fc;">→ {_esc(action)}</div></div>' if action else ''}
    {links_html}
  </div>
'''


def _esc(text: str) -> str:
    """HTML escape"""
    if not text:
        return ''
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def _parse_json_field(value) -> dict:
    """Parse a JSON field that might be a string or dict"""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _chart_colors(n: int) -> list:
    """Generate n distinct colors for charts"""
    palette = [
        '#6366f1', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316',
        '#eab308', '#22c55e', '#14b8a6', '#06b6d4', '#3b82f6',
        '#a855f7', '#d946ef', '#fb7185', '#fbbf24', '#34d399',
    ]
    if n <= len(palette):
        return palette[:n]
    # Repeat with variations
    colors = []
    for i in range(n):
        colors.append(palette[i % len(palette)])
    return colors
