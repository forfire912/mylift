# MyLift – SAST 结果分析平台

> 静态扫描结果分析（Static Application Security Testing result analysis）

MyLift 是一个 **全栈 Web 应用**，用于上传、解析和可视化 SAST 工具的扫描结果。

---

## 功能特性

- **多格式支持**：SARIF 2.1.0、Semgrep、Bandit、Checkov、Trivy 以及通用 JSON 格式
- **漏洞管理**：按严重程度、规则 ID 筛选漏洞，点击展开详情及代码片段
- **总览仪表盘**：可视化展示漏洞严重程度分布和工具使用情况
- **报告管理**：上传、查看、删除扫描报告
- **安全设计**：路径穿越防护、输入验证

---

## 技术栈

| 层 | 技术 |
|----|------|
| **后端** | Python 3.12 · FastAPI · SQLAlchemy · SQLite |
| **前端** | React 18 · TypeScript · Vite |
| **测试** | pytest · FastAPI TestClient |
| **部署** | Docker Compose |

---

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
docker compose up
```

- 前端：http://localhost:5173
- 后端 API：http://localhost:8000
- API 文档：http://localhost:8000/docs

### 方式二：本地开发

**后端**

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload
# 访问 http://localhost:8000/docs 查看 API 文档
```

**前端**

```bash
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

---

## 运行测试

```bash
python -m pytest tests/ -v
```

---

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/upload` | 上传扫描结果文件 |
| `GET` | `/api/reports` | 获取报告列表 |
| `GET` | `/api/reports/{id}` | 获取报告详情（含漏洞列表） |
| `DELETE` | `/api/reports/{id}` | 删除报告 |
| `GET` | `/api/reports/{id}/vulnerabilities` | 获取漏洞列表（支持按严重程度/规则 ID 筛选） |
| `GET` | `/api/stats` | 获取全局统计信息 |
| `GET` | `/health` | 健康检查 |

---

## 目录结构

```
mylift/
├── backend/
│   ├── main.py           # FastAPI 应用入口
│   ├── database.py       # SQLAlchemy 模型与数据库配置
│   ├── models.py         # Pydantic 请求/响应模型
│   ├── api/
│   │   └── routes.py     # REST API 路由
│   ├── parsers/
│   │   ├── sarif.py      # SARIF 格式解析器
│   │   └── json_parser.py# JSON 格式解析器（多工具自动检测）
│   └── context/
│       └── enricher.py   # 代码上下文提取工具
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/   # Dashboard / ReportList / ReportDetail / Upload
│   │   └── services/
│   │       └── api.ts    # 后端 API 服务层
│   └── index.html
├── tests/
│   ├── test_api.py       # API 集成测试（28 个）
│   ├── test_parsers.py   # 解析器单元测试
│   └── test_enricher.py  # 上下文提取器测试
├── requirements.txt
├── pytest.ini
└── docker-compose.yml
```
