# MyLift - 智能静态分析系统

基于 **LLM + Agent + 多SAST** 的智能静态分析系统，实现静态分析结果的自动化分析、误报识别与风险排序。

## 系统架构

```
SAST工具输入层（Cppcheck / Coverity / Klocwork）
        ↓
解析与标准化层（Adapter → SARIF 2.1.0）
        ↓
上下文增强层（代码片段 / 函数定位 / 执行路径）
        ↓
LLM Agent 推理层（4个Agent串联）
        ↓
风险评分引擎（SAST Severity + LLM Confidence + Exploitability + Context）
        ↓
Web 平台展示（漏洞列表 / 详情 / 统计分析）
```

## 功能特性

- **多工具支持**：Cppcheck (XML)、Coverity (JSON)、Klocwork (JSON)
- **SARIF 统一标准**：所有工具输出转换为 SARIF 2.1.0 格式
- **代码上下文提取**：±30行代码片段、函数名定位、执行路径构建
- **4-Agent LLM 分析流程**（参考 LLift 设计）：
  - Agent 1：代码理解（变量关系、控制逻辑）
  - Agent 2：路径分析（执行路径可达性判断）
  - Agent 3：漏洞判定（真实漏洞 vs 误报，含置信度）
  - Agent 4：修复建议（补丁代码 + 最佳实践）
- **风险评分**：综合 SAST 严重性 + LLM 置信度 + 可利用性 + 代码上下文
- **Web 平台**：漏洞列表（按风险排序/过滤）、详情页（代码高亮 + LLM 分析）、统计图表

## 技术栈

| 层次 | 技术 |
|------|------|
| 后端 | FastAPI + SQLAlchemy + Alembic |
| 数据库 | SQLite（可换 MySQL） |
| 任务队列 | Celery + Redis |
| LLM | OpenAI API（可配置本地模型） |
| 前端 | React + TypeScript + Vite |
| 图表 | Recharts |
| 容器化 | Docker + Docker Compose |

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
# 1. 配置 OpenAI Key
cp .env.example .env
# 编辑 .env，填写 OPENAI_API_KEY

# 2. 启动所有服务
docker-compose up -d

# 访问 Web UI: http://localhost:3000
# 访问 API 文档: http://localhost:8000/api/docs
```

### 方式二：本地开发

**后端：**
```bash
cd backend
pip install -r requirements.txt

# 配置环境变量
export OPENAI_API_KEY=your_key_here

# 启动后端
uvicorn backend.main:app --reload --port 8000

# 启动 Celery Worker（可选，需要 Redis）
celery -A backend.tasks.celery_tasks.celery_app worker --loglevel=info
```

**前端：**
```bash
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `OPENAI_API_KEY` | - | OpenAI API Key |
| `OPENAI_MODEL` | `gpt-4o` | 使用的模型 |
| `OPENAI_BASE_URL` | - | 自定义 API 地址（本地模型） |
| `DATABASE_URL` | `sqlite:///./mylift.db` | 数据库连接 |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis 地址 |
| `CODE_CONTEXT_LINES` | `30` | 代码上下文行数 |

## API 文档

启动后访问 `http://localhost:8000/api/docs` 查看完整 API 文档。

### 主要接口

```
POST /api/v1/tasks              - 上传 SAST 扫描结果
GET  /api/v1/tasks              - 获取任务列表
POST /api/v1/tasks/{id}/analyze - 触发 LLM 分析
GET  /api/v1/findings           - 漏洞列表（支持过滤/分页）
GET  /api/v1/findings/{id}      - 漏洞详情
POST /api/v1/findings/{id}/analyze - 单个漏洞分析
PATCH /api/v1/findings/{id}/false-positive - 标记误报
GET  /api/v1/stats              - 统计信息
```

## 运行测试

```bash
cd /path/to/mylift
python -m pytest tests/ -v
```

## 风险评分公式

```
Risk Score = SAST_Severity (0-40)
           + LLM_Confidence × 35 (如果确认漏洞)
           + Trace_Depth × 3 (最大15，执行路径深度)
           + Code_Context_Risk (0-10，危险API关键词)
```

评分阈值：≥80 → 严重，≥60 → 高危，≥40 → 中危，≥20 → 低危，其他 → 信息
