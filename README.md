# Intelligence System

> AI-powered vulnerability intelligence platform — crawl GHSA advisories, run LLM deep analysis, generate daily reports, and deliver via OSS.

中文名：**情报系统** —— 自动采集 GitHub Security Advisories（GHSA），用 LLM 做深度研判，生成每日漏洞情报简报并推送至 OSS 存储。

## ✨ Features

- **Advisory Crawling** — 自动爬取 GHSA 漏洞公告并结构化入库
- **LLM Deep Analysis** — 通过 NVIDIA / DeepSeek / Sub2API 代理等小模型路由，对漏洞做深度研判
- **Daily Reports** — 自动生成每日漏洞情报简报
- **OSS Delivery** — 将产物推送至 OSS 兼容存储
- **Structured Storage** — 核心结构化数据持久化于 MySQL

## 🏗️ Architecture

```
GHSA Source
   │  crawl & normalize
   ▼
LLM Analysis Pipeline ──► Structured Store (MySQL)
   │                         │
   │ daily report            ▼
   ▼                    OSS-compatible Storage (artifacts)
Daily Report Generator
```

- **Data layer**: MySQL（结构化数据）+ OSS 兼容存储（静态文件 / 大产物）
- **Model routing**: 通过 NVIDIA / DeepSeek / Sub2API-proxied providers 调度小模型
- **Spec-first scaffold**: 需求、设计、任务、数据模型、流水线、API、部署文档均位于 `.spec/`

## 🧱 Tech Stack

- **Language**: Python（主力）
- **Storage**: MySQL + OSS-compatible object storage
- **Models**: NVIDIA · DeepSeek · Sub2API-proxied providers
- **Tooling**: `make`（lint / verify / 迁移与注释策略检查）· Ruff

## 🚀 Quick Start

```bash
# clone
git clone https://github.com/e1evensu/intelligence-system.git
cd intelligence-system

# install
pip install -r requirements.txt      # or: make bootstrap

# configure
cp .env.example .env
# set DATABASE_URL / OSS_*/ MODEL_PROVIDER_* ...

# run
python -m intelligence_system        # or: make run
```

> **Runtime note**: `DATABASE_VERIFY_TLS=false` 保持当前的跨境部署行为（加密 MySQL 流量但接受自签名证书）。
> 仅在运行时能提供可验证证书链与主机名后，才将 `DATABASE_VERIFY_TLS` 置为 `true`。

## 📚 Documentation

当前 SPECs 为草稿评审文档（用于实现前的分析）：

- Requirements `.spec/requirements.md` · Design `.spec/design.md`
- Tasks & review gates `.spec/tasks.md` · Data model `.spec/data-model.md`
- Pipeline `.spec/pipeline.md` · Model routing `.spec/model-routing.md`
- API `.spec/api.md` · Deployment `.spec/deployment.md`
- Architecture decisions `docs/decisions/` · Tech-debt review `docs/TECH_DEBT_REVIEW.md`

## 🔍 Quality Gates

```bash
make check-comments    # 轻量注释策略检查
make check-migrations  # 编号化 SQL 迁移命名与发现
make check-frontend    # 前端 window-export 白名单
make lint              # Ruff + 注释策略检查
make verify            # lint + tests + 编译检查
```

## 📄 License

[Apache-2.0](LICENSE)
