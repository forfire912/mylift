import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import apiService, { Finding, FindingListResponse } from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import RiskBar from '../components/RiskBar'
import { useProgress } from '../context/ProgressContext'

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
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const [batchSubmitting, setBatchSubmitting] = useState(false)
  const { openPanel } = useProgress()

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
  useEffect(() => { setSelectedIds([]) }, [taskId, filterTool, filterSeverity, filterVulnerable, page])

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1
  const visibleIds = data?.items.map(item => item.id) || []
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every(id => selectedIds.includes(id))
  const selectedCount = selectedIds.length

  const handleMarkFP = async (finding: Finding, e: React.MouseEvent) => {
    e.stopPropagation()
    await apiService.markFalsePositive(finding.id, !finding.is_false_positive)
    load()
  }

  const handleAnalyze = async (finding: Finding, e: React.MouseEvent) => {
    e.stopPropagation()
    await apiService.analyzeFinding(finding.id)
    openPanel(finding.task_id)
    alert(`Finding #${finding.id} 已提交 LLM 分析`)
  }

  const toggleSelected = (findingId: number, checked: boolean) => {
    setSelectedIds(prev => checked ? [...new Set([...prev, findingId])] : prev.filter(id => id !== findingId))
  }

  const toggleSelectVisible = (checked: boolean) => {
    setSelectedIds(prev => {
      if (checked) {
        return [...new Set([...prev, ...visibleIds])]
      }
      return prev.filter(id => !visibleIds.includes(id))
    })
  }

  const handleBatchAnalyze = async () => {
    if (selectedIds.length === 0) {
      alert('请先选择要分析的漏洞')
      return
    }
    if (!window.confirm(`确定要对选中的 ${selectedIds.length} 个漏洞发起批量 LLM 分析吗？`)) return
    setBatchSubmitting(true)
    try {
      await apiService.analyzeFindings(selectedIds)
      const firstSelected = data?.items.find(item => item.id === selectedIds[0])
      if (firstSelected) openPanel(firstSelected.task_id)
      alert(`已提交 ${selectedIds.length} 个漏洞进行 LLM 批量分析`)
      setSelectedIds([])
    } catch {
      alert('批量分析提交失败，请稍后重试')
    } finally {
      setBatchSubmitting(false)
    }
  }

  const handleBatchMarkFalsePositive = async (isFalsePositive: boolean) => {
    if (selectedIds.length === 0) {
      alert(`请先选择要${isFalsePositive ? '标记' : '取消'}的漏洞`)
      return
    }
    if (!window.confirm(`确定要${isFalsePositive ? '标记' : '取消'}这 ${selectedIds.length} 个漏洞的误报状态吗？`)) return
    setBatchSubmitting(true)
    try {
      await apiService.markFalsePositiveBatch(selectedIds, isFalsePositive)
      alert(`已${isFalsePositive ? '标记' : '取消'} ${selectedIds.length} 个漏洞为误报`)
      setSelectedIds([])
      await load()
    } catch {
      alert(`批量${isFalsePositive ? '标记' : '取消'}误报失败，请稍后重试`)
    } finally {
      setBatchSubmitting(false)
    }
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
        <button className="btn btn-toolbar btn-toolbar-primary" onClick={handleBatchAnalyze} disabled={batchSubmitting || selectedIds.length === 0}>
          {batchSubmitting ? '提交中...' : `LLM 分析${selectedIds.length > 0 ? ` (${selectedIds.length})` : ''}`}
        </button>
        <button className="btn btn-toolbar" onClick={() => handleBatchMarkFalsePositive(true)} disabled={batchSubmitting || selectedIds.length === 0}>
          标记误报{selectedIds.length > 0 ? ` (${selectedIds.length})` : ''}
        </button>
        <button className="btn btn-toolbar" onClick={() => handleBatchMarkFalsePositive(false)} disabled={batchSubmitting || selectedIds.length === 0}>
          误报回退{selectedIds.length > 0 ? ` (${selectedIds.length})` : ''}
        </button>
      </div>

      {selectedCount > 0 && (
        <div className="card" style={{ padding: '10px 16px', marginBottom: 16, background: '#fafafa' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <div style={{ fontSize: 13, color: '#555' }}>
              已选择 <strong>{selectedCount}</strong> 条漏洞，当前页共 {visibleIds.length} 条
            </div>
            <button className="btn btn-default" onClick={() => setSelectedIds([])} disabled={batchSubmitting}>
              清空选择
            </button>
          </div>
        </div>
      )}

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
                    <th style={{ width: 44 }}>
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        onChange={e => toggleSelectVisible(e.target.checked)}
                        aria-label="选择当前页全部漏洞"
                      />
                    </th>
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
                    (() => {
                      const isFalsePositive = f.is_false_positive || f.is_vulnerable === false
                      return (
                    <tr
                      key={f.id}
                      style={{ cursor: 'pointer', opacity: isFalsePositive ? 0.65 : 1 }}
                      onClick={() => navigate(`/findings/${f.id}`)}
                    >
                      <td onClick={e => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(f.id)}
                          onChange={e => toggleSelected(f.id, e.target.checked)}
                          aria-label={`选择漏洞 ${f.id}`}
                        />
                      </td>
                      <td style={{ color: '#888', fontSize: 13 }}>#{f.id}</td>
                      <td><span style={{ fontSize: 12 }}>{f.tool}</span></td>
                      <td style={{ fontFamily: 'monospace', fontSize: 13 }}>{f.rule_id}</td>
                      <td style={{ fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {f.file_path && `${f.file_path}:${f.line_start}`}
                      </td>
                      <td><SeverityBadge severity={f.sast_severity} /></td>
                      <td><SeverityBadge severity={isFalsePositive ? 'false_positive' : f.final_severity} /></td>
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
                          <button
                            className="btn btn-primary"
                            style={{ fontSize: 12, padding: '2px 8px' }}
                            onClick={e => handleAnalyze(f, e)}
                          >
                            {f.analyzed_at === null ? '分析' : '重新分析'}
                          </button>
                        </div>
                      </td>
                    </tr>
                      )
                    })()
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
