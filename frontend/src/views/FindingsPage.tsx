import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import apiService, { Finding, FindingListResponse } from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import RiskBar from '../components/RiskBar'

const PAGE_SIZE = 20

export default function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()

  const taskId = searchParams.get('task_id') ? parseInt(searchParams.get('task_id')!) : undefined
  const [filterTool, setFilterTool] = useState(searchParams.get('tool') || '')
  const [filterSeverity, setFilterSeverity] = useState(searchParams.get('severity') || '')
  const [filterVulnerable, setFilterVulnerable] = useState(searchParams.get('vulnerable') || '')
  const [page, setPage] = useState(1)

  const [data, setData] = useState<FindingListResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = { page, page_size: PAGE_SIZE }
      if (taskId) params.task_id = taskId
      if (filterTool) params.tool = filterTool
      if (filterSeverity) params.severity = filterSeverity
      if (filterVulnerable !== '') params.is_vulnerable = filterVulnerable === 'true'
      const r = await apiService.listFindings(params)
      setData(r.data)
    } finally {
      setLoading(false)
    }
  }, [taskId, filterTool, filterSeverity, filterVulnerable, page])

  useEffect(() => { load() }, [load])

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1

  const handleMarkFP = async (finding: Finding, e: React.MouseEvent) => {
    e.stopPropagation()
    await apiService.markFalsePositive(finding.id, !finding.is_false_positive)
    load()
  }

  const handleAnalyze = async (finding: Finding, e: React.MouseEvent) => {
    e.stopPropagation()
    await apiService.analyzeFinding(finding.id)
    alert(`Finding #${finding.id} 已提交 LLM 分析`)
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          漏洞列表 {taskId && <span style={{ fontSize: 15, color: '#888', fontWeight: 400 }}>（任务 #{taskId}）</span>}
        </h1>
        {data && <span style={{ color: '#888', fontSize: 14 }}>共 {data.total} 条</span>}
      </div>

      <div className="filter-bar card" style={{ padding: '12px 20px' }}>
        <select className="form-select" value={filterTool} onChange={e => { setFilterTool(e.target.value); setPage(1) }}>
          <option value="">所有工具</option>
          <option value="cppcheck">Cppcheck</option>
          <option value="coverity">Coverity</option>
          <option value="klocwork">Klocwork</option>
        </select>
        <select className="form-select" value={filterSeverity} onChange={e => { setFilterSeverity(e.target.value); setPage(1) }}>
          <option value="">所有严重级别</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
          <option value="info">信息</option>
        </select>
        <select className="form-select" value={filterVulnerable} onChange={e => { setFilterVulnerable(e.target.value); setPage(1) }}>
          <option value="">所有状态</option>
          <option value="true">确认漏洞</option>
          <option value="false">误报</option>
        </select>
        <button className="btn btn-default" onClick={() => { setFilterTool(''); setFilterSeverity(''); setFilterVulnerable(''); setPage(1) }}>
          重置过滤
        </button>
      </div>

      {loading ? (
        <div className="loading">加载中...</div>
      ) : !data || data.items.length === 0 ? (
        <div className="empty-state">暂无漏洞数据</div>
      ) : (
        <>
          <div className="card" style={{ padding: 0 }}>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>工具</th>
                    <th>规则</th>
                    <th>文件位置</th>
                    <th>SAST 严重性</th>
                    <th>最终严重性</th>
                    <th>风险评分</th>
                    <th>LLM 判断</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map(f => (
                    <tr
                      key={f.id}
                      style={{ cursor: 'pointer', opacity: f.is_false_positive ? 0.5 : 1 }}
                      onClick={() => navigate(`/findings/${f.id}`)}
                    >
                      <td style={{ color: '#888', fontSize: 13 }}>#{f.id}</td>
                      <td><span style={{ fontSize: 12 }}>{f.tool}</span></td>
                      <td style={{ fontFamily: 'monospace', fontSize: 13 }}>{f.rule_id}</td>
                      <td style={{ fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {f.file_path && `${f.file_path}:${f.line_start}`}
                      </td>
                      <td><SeverityBadge severity={f.sast_severity} /></td>
                      <td><SeverityBadge severity={f.final_severity} /></td>
                      <td style={{ minWidth: 120 }}><RiskBar score={f.risk_score} /></td>
                      <td>
                        {f.is_vulnerable === null ? (
                          <span style={{ color: '#bbb', fontSize: 13 }}>待分析</span>
                        ) : f.is_vulnerable ? (
                          <span style={{ color: '#cf1322', fontSize: 13, fontWeight: 600 }}>
                            ⚠ 确认 ({f.llm_confidence ? `${Math.round(f.llm_confidence * 100)}%` : ''})
                          </span>
                        ) : (
                          <span style={{ color: '#52c41a', fontSize: 13 }}>
                            ✓ 误报 ({f.llm_confidence ? `${Math.round(f.llm_confidence * 100)}%` : ''})
                          </span>
                        )}
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            className="btn btn-default"
                            style={{ fontSize: 12, padding: '2px 8px' }}
                            onClick={e => handleMarkFP(f, e)}
                          >
                            {f.is_false_positive ? '取消误报' : '标记误报'}
                          </button>
                          {f.analyzed_at === null && (
                            <button
                              className="btn btn-primary"
                              style={{ fontSize: 12, padding: '2px 8px' }}
                              onClick={e => handleAnalyze(f, e)}
                            >
                              分析
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pagination">
            <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}>上一页</button>
            <span style={{ fontSize: 14, color: '#666' }}>第 {page} / {totalPages} 页</span>
            <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>下一页</button>
          </div>
        </>
      )}
    </div>
  )
}
