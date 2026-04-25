# GHSA Intel Service — 微服务需求文档

## 目标

每日自动从 GitHub Security Advisories (GHSA) 抓取最新高危安全公告，AI 分析后生成中文日报，推送到飞书。

## 架构：本地微服务 + Cron 调度

不使用 GitHub Actions（picker 那种模式），直接在本地运行 Python 微服务，Hermes cron 每天触发。

```
每日 Cron
  → main.py
    → fetch: GHSA REST API 抓取最近 24h 高危 advisory
    → enrich: 补充仓库 star 数、CVE 详情、fix commit
    → filter: 严格过滤（见下方）
    → analyze: AI 生成中文分析（摘要 + 影响评估 + 利用难度）
    → render: 生成 HTML 日报
    → push: 推送到飞书
```

## 核心要求

### 1. 数据获取

使用 GitHub REST API `GET /advisories` 端点：
- URL: `https://api.github.com/advisories`
- 参数: `sort=published&direction=desc&per_page=100`
- 需要 GitHub Token（`GITHUB_TOKEN` 环境变量）避免 rate limit
- 筛选条件直接在 API 查询中：`severity=critical,high`

### 2. 严格过滤（Curator 策略，借鉴 N-Day-Bench）

每条 advisory 必须同时满足：

| 条件 | 原因 |
|------|------|
| 有 CVE ID（`identifiers` 里 type=CVE） | 确认是已确认漏洞 |
| severity = HIGH 或 CRITICAL | 只关注高危 |
| 有 `references` 包含修复链接 | 确认有补丁 |
| 关联仓库存在且 star > 1000 | 过滤小众项目噪音 |
| published_at 在最近 48 小时内 | 保持时效性 |
| 类型为 `reviewed`（非 `malware`/`unreviewed`） | 只取人工审核过的 |

预期：每天过滤后剩余 5-20 条。

### 3. Enrichment（信息补充）

对每条通过的 advisory：
- 查询关联仓库的 star 数、语言、最近活跃度
- 如果有 fix commit，提取变更的文件列表
- 检查 CISA KEV 列表（https://www.cisa.gov/known-exploited-vulnerabilities-catalog）中是否存在该 CVE
- 检查是否有公开 exploit（GitHub 搜索 CVE 编号）

### 4. AI 分析

使用 LiteLLM（复用 TrendRadar 的方案），对每条漏洞生成：

```
- 漏洞类型：一句话
- 影响范围：受影响的组件/版本
- 利用难度：[高/中/低] + 理由
- 紧急程度：[🔴紧急/🟠高危/🟡关注]
- 中文摘要：≤200 字
- 建议动作：是否需要立即升级
```

### 5. 日报格式

HTML 格式，飞书兼容：

```
安全漏洞日报 — 2026-04-25
━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 紧急 (N 条)
┌─────────────────────────────
│ CVE-2026-XXXX | CVSS 9.8
│ 项目：xxx/xxx (⭐ 50k)
│ 类型：远程代码执行
│ 摘要：...
│ 利用难度：低 — 已有公开 PoC
│ 建议动作：立即升级到 vX.X.X
└─────────────────────────────

🟠 高危 (N 条)
...

🟡 值得关注 (N 条)
...

📊 今日统计
- 总抓取：XX 条
- 过滤后：XX 条
- 紧急：X | 高危：X | 关注：X
- 本周趋势：+XX% vs 上周
```

### 6. 技术栈

- Python 3.11+
- `requests` / `httpx` — HTTP 请求
- `jinja2` — HTML 模板渲染
- `litellm` — AI 分析（DeepSeek 或其他廉价模型做摘要）
- `sqlite3` — 本地存储历史数据（去重 + 趋势统计）
- 飞书 Webhook — 推送

### 7. 项目结构

```
~/intel-projects/ghsa-intel/
├── main.py              # 入口，cron 触发
├── config.py            # 配置（token、模型、webhook）
├── fetcher.py           # GHSA API 抓取
├── curator.py           # 过滤 + enrichment
├── analyzer.py          # AI 分析
├── renderer.py          # HTML 日报生成
├── pusher.py            # 飞书推送
├── db.py                # SQLite 操作
├── templates/
│   └── daily_report.html  # Jinja2 日报模板
├── requirements.txt
└── data/
    └── ghsa_intel.db    # SQLite 数据库
```

### 8. 数据持久化

SQLite 表结构：
- `advisories`: ghsa_id, cve_id, summary, severity, published_at, repo, stars, cvss, analyzed_summary, urgency, created_at
- `daily_reports`: date, advisory_count, html_path, pushed
- 用于去重、趋势统计、历史回溯

### 9. 推送

飞书 Webhook，发送 HTML 富文本卡片。如果 HTML 卡片不支持，发送纯文本摘要 + OSS 下载链接。

## 实现优先级

1. **fetcher.py** — 能从 GHSA API 拉数据
2. **curator.py** — 过滤出高质量条目
3. **db.py** — 存 SQLite，去重
4. **analyzer.py** — AI 生成中文摘要
5. **renderer.py** — HTML 日报
6. **pusher.py** — 飞书推送
7. **main.py** — 串联所有模块
8. Cron 配置

## 关键约束

- GitHub Token 通过环境变量 `GITHUB_TOKEN` 传入
- AI 模型优先 DeepSeek（便宜），fallback 到其他模型
- 日报中文
- 不依赖 Docker，直接 Python 运行
- 不依赖 GitHub Actions，本地 cron
