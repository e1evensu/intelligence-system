# intelligence-system

安全漏洞情报系统 — GHSA 爬取 / AI 深度分析 / 日报生成 / OSS 推送

## 项目结构

```
├── config.py              # 全局配置（从 .env 读）
├── main.py                # 入口
├── .env                   # 密钥配置（不入库）
├── .env.example           # 配置模板
├── modules/
│   └── ghsa/              # GHSA 漏洞情报模块
│       ├── __init__.py
│       ├── fetcher.py     # GHSA API 爬取
│       ├── curator.py     # 过滤/排序/enrichment
│       ├── analyzer.py    # SiliconFlow AI 深度分析
│       ├── db.py          # SQLite 存储
│       ├── renderer.py    # HTML 日报生成
│       └── pusher.py      # OSS 上传
├── data/                  # SQLite DB（不入库）
└── reports/               # 生成的日报 HTML（不入库）
```

## 运行

```bash
cp .env.example .env  # 填入真实密钥
python main.py
```

## 日报输出

- 本地：`reports/YYYY-MM-DD/index.html`
- OSS：`https://{bucket}.oss-cn-guangzhou.aliyuncs.com/subot/ghsa-daily/YYYY-MM-DD`
