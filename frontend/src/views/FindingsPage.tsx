import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import apiService, {
  AnalysisTarget,
  Finding,
  FindingListResponse,
  IssueGroup,
  IssueGroupListResponse,
} from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import RiskBar from '../components/RiskBar'
import { useProgress } from '../context/ProgressContext'

const PAGE_SIZE = 20

export default function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const { openPanel } = useProgress()

  const taskId = searchParams.get('task_id') ? parseInt(searchParams.get('task_id')!, 10) : undefined
  const [viewMode, setViewMode] = useState<AnalysisTarget>((searchParams.get('view') as AnalysisTarget) || 'issue_group')
  const [filterTool, setFilterTool] = useState(searchParams.get('tool') || '')
  const [filterSeverity, setFilterSeverity] = useState(searchParams.get('severity') || '')
  const [filterAnalyzed, setFilterAnalyzed] = useState(searchParams.get('analyzed') || '')
  const [filterVulnerable, setFilterVulnerable] = useState(searchParams.get('vulnerable') || '')
  const [page, setPage] = useState(searchParams.get('page') ? parseInt(searchParams.get('page')!, 10) : 1)

  const [findingData, setFindingData] = useState<FindingListResponse | null>(null)
  const [issueGroupData, setIssueGroupData] = useState<IssueGroupListResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const [batchSubmitting, setBatchSubmitting] = useState(false)

  useEffect(() => {
    const nextParams = new URLSearchParams()
    if (taskId) nextParams.set('task_id', String(taskId))
    if (viewMode !== 'issue_group') nextParams.set('view', viewMode)
    if (filterTool) nextParams.set('tool', filterTool)
    if (filterSeverity) nextParams.set('severity', filterSeverity)
    if (filterAnalyzed) nextParams.set('analyzed', filterAnalyzed)
    if (filterVulnerable) nextParams.set('vulnerable', filterVulnerable)
    if (page > 1) nextParams.set('page', String(page))
    setSearchParams(nextParams, { replace: true })
  }, [filterAnalyzed, filterSeverity, filterTool, filterVulnerable, page, setSearchParams, taskId, viewMode])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: {
        task_id?: number
        tool?: string
        severity?: string
        analyzed?: boolean
        is_vulnerable?: boolean
        page: number
        page_size: number
      } = {
        page,
        page_size: PAGE_SIZE,
      }

      if (taskId) params.task_id = taskId
      if (filterTool) params.tool = filterTool
      if (filterSeverity) params.severity = filterSeverity
      if (filterAnalyzed !== '') params.analyzed = filterAnalyzed === 'true'
      if (filterVulnerable !== '') params.is_vulnerable = filterVulnerable === 'true'

      if (viewMode === 'issue_group') {
        const response = await apiService.listIssueGroups(params)
        setIssueGroupData(response.data)
        setFindingData(null)
      } else {
        const response = await apiService.listFindings(params)
        setFindingData(response.data)
        setIssueGroupData(null)
      }
    } finally {
      setLoading(false)
    }
  }, [filterAnalyzed, filterSeverity, filterTool, filterVulnerable, page, taskId, viewMode])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setSelectedIds([])
  }, [filterAnalyzed, filterSeverity, filterTool, filterVulnerable, page, taskId, viewMode])

  const currentData = useMemo(() => (
    viewMode === 'issue_group' ? issueGroupData : findingData
  ), [findingData, issueGroupData, viewMode])

  const totalPages = currentData ? Math.max(1, Math.ceil(currentData.total / PAGE_SIZE)) : 1
  const visibleIds = useMemo(() => currentData?.items.map(item => item.id) || [], [currentData])
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every(id => selectedIds.includes(id))
  const selectedCount = selectedIds.length

  const handleResetFilters = () => {
    setFilterTool('')
    setFilterSeverity('')
    setFilterAnalyzed('')
    setFilterVulnerable('')
    setPage(1)
  }

  const toggleSelected = (itemId: number, checked: boolean) => {
    setSelectedIds(prev => (checked ? [...new Set([...prev, itemId])] : prev.filter(id => id !== itemId)))
  }

  const toggleSelectVisible = (checked: boolean) => {
    setSelectedIds(prev => {
      if (checked) {
        return [...new Set([...prev, ...visibleIds])]
      }
      return prev.filter(id => !visibleIds.includes(id))
    })
  }

  const handleAnalyzeFinding = async (finding: Finding, event: React.MouseEvent) => {
    event.stopPropagation()
    await apiService.analyzeFinding(finding.id)
    openPanel(finding.task_id)
    alert(`Finding #${finding.id} 已提交 LLM 分析`)
  }

  const handleAnalyzeIssueGroup = async (issueGroup: IssueGroup, event: React.MouseEvent) => {
    event.stopPropagation()
    await apiService.analyzeIssueGroup(issueGroup.id)
    openPanel(issueGroup.task_id)
    alert(`问题组 #${issueGroup.id} 已提交 LLM 分析`)
  }

  const handleMarkFindingFalsePositive = async (finding: Finding, event: React.MouseEvent) => {
    event.stopPropagation()
    await apiService.markFalsePositive(finding.id, !finding.is_false_positive)
    await load()
  }

  const handleMarkIssueGroupFalsePositive = async (issueGroup: IssueGroup, event: React.MouseEvent) => {
    event.stopPropagation()
    await apiService.markIssueGroupFalsePositive(issueGroup.id, !issueGroup.is_false_positive)
    await load()
  }

  const handleBatchAnalyze = async () => {
    if (selectedIds.length === 0) {
      alert(viewMode === 'issue_group' ? '请先选择要分析的问题组' : '请先选择要分析的漏洞')
      return
    }

    const noun = viewMode === 'issue_group' ? '问题组' : '漏洞'
    if (!window.confirm(`确定要对选中的 ${selectedIds.length} 个${noun}发起 LLM 分析吗？`)) return

    setBatchSubmitting(true)
    try {
      if (viewMode === 'issue_group') {
        await apiService.analyzeIssueGroups(selectedIds)
        const firstSelected = issueGroupData?.items.find(item => item.id === selectedIds[0])
        if (firstSelected) openPanel(firstSelected.task_id)
      } else {
        await apiService.analyzeFindings(selectedIds)
        const firstSelected = findingData?.items.find(item => item.id === selectedIds[0])
        if (firstSelected) openPanel(firstSelected.task_id)
      }
      alert(`已提交 ${selectedIds.length} 个${noun}进行 LLM 分析`)
      setSelectedIds([])
    } catch {
      alert('批量分析提交失败，请稍后重试')
    } finally {
      setBatchSubmitting(false)
    }
  }

  const handleBatchMarkFalsePositive = async (isFalsePositive: boolean) => {
    if (selectedIds.length === 0) {
      alert(viewMode === 'issue_group'
        ? `请先选择要${isFalsePositive ? '标记' : '回退'}的问题组`
        : `请先选择要${isFalsePositive ? '标记' : '回退'}的漏洞`)
      return
    }

    const noun = viewMode === 'issue_group' ? '问题组' : '漏洞'
    const action = isFalsePositive ? '标记为误报' : '执行误报回退'
    if (!window.confirm(`确定要对这 ${selectedIds.length} 个${noun}${action}吗？`)) return

    setBatchSubmitting(true)
    try {
      if (viewMode === 'issue_group') {
        await apiService.markIssueGroupFalsePositiveBatch(selectedIds, isFalsePositive)
      } else {
        await apiService.markFalsePositiveBatch(selectedIds, isFalsePositive)
      }
      alert(`已对 ${selectedIds.length} 个${noun}${isFalsePositive ? '标记误报' : '完成误报回退'}`)
      setSelectedIds([])
      await load()
    } catch {
      alert(`${isFalsePositive ? '标记误报' : '误报回退'}失败，请稍后重试`)
    } finally {
      setBatchSubmitting(false)
    }
  }

  const renderVerdict = (item: Finding | IssueGroup) => {
    if (item.is_vulnerable === null) {
      return <span style={{ color: '#bbb', fontSize: 13 }}>待分析</span>
    }
    if (item.is_vulnerable) {
      return (
        <span style={{ color: '#cf1322', fontSize: 13, fontWeight: 600 }}>
          确认{item.llm_confidence ? ` (${Math.round(item.llm_confidence * 100)}%)` : ''}
        </span>
      )
    }
    return (
      <span style={{ color: '#52c41a', fontSize: 13 }}>
        误报{item.llm_confidence ? ` (${Math.round(item.llm_confidence * 100)}%)` : ''}
      </span>
    )
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          {viewMode === 'issue_group' ? '问题组列表' : '漏洞列表'}
          {taskId && <span style={{ fontSize: 15, color: '#888', fontWeight: 400 }}>（任务 #{taskId}）</span>}
        </h1>
        {currentData && <span style={{ color: '#888', fontSize: 14 }}>共 {currentData.total} 条</span>}
      </div>

      <div className="filter-bar card" style={{ padding: '12px 20px' }}>
        <select className="form-select" value={viewMode} onChange={event => { setViewMode(event.target.value as AnalysisTarget); setPage(1) }}>
          <option value="issue_group">查看问题组</option>
          <option value="finding">查看原始漏洞</option>
        </select>
        <select className="form-select" value={filterTool} onChange={event => { setFilterTool(event.target.value); setPage(1) }}>
          <option value="">所有工具</option>
          <option value="cppcheck">Cppcheck</option>
          <option value="coverity">Coverity</option>
          <option value="klocwork">Klocwork</option>
        </select>
        <select className="form-select" value={filterSeverity} onChange={event => { setFilterSeverity(event.target.value); setPage(1) }}>
          <option value="">所有严重级别</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
          <option value="info">信息</option>
        </select>
        <select className="form-select" value={filterAnalyzed} onChange={event => { setFilterAnalyzed(event.target.value); setPage(1) }}>
          <option value="">所有分析状态</option>
          <option value="true">已分析</option>
          <option value="false">未分析</option>
        </select>
        <select className="form-select" value={filterVulnerable} onChange={event => { setFilterVulnerable(event.target.value); setPage(1) }}>
          <option value="">所有状态</option>
          <option value="true">确认漏洞</option>
          <option value="false">误报</option>
        </select>
        <button className="btn btn-default" onClick={handleResetFilters}>重置过滤</button>
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
              已选择 <strong>{selectedCount}</strong> 条{viewMode === 'issue_group' ? '问题组' : '漏洞'}，当前页共 {visibleIds.length} 条
            </div>
            <button className="btn btn-default" onClick={() => setSelectedIds([])} disabled={batchSubmitting}>
              清空选择
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="loading">加载中...</div>
      ) : !currentData || currentData.items.length === 0 ? (
        <div className="empty-state">暂无{viewMode === 'issue_group' ? '问题组' : '漏洞'}数据</div>
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
                        onChange={event => toggleSelectVisible(event.target.checked)}
                        aria-label="选择当前页全部项目"
                      />
                    </th>
                    <th>ID</th>
                    {viewMode === 'issue_group' && <th>成员数</th>}
                    <th>工具</th>
                    <th>规则</th>
                    <th>文件位置</th>
                    <th>{viewMode === 'issue_group' ? '归并后严重性' : '最终严重性'}</th>
                    <th>风险评分</th>
                    <th>LLM 判断</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {viewMode === 'issue_group' ? issueGroupData?.items.map(group => {
                    const isFalsePositive = group.is_false_positive || group.is_vulnerable === false
                    return (
                      <tr
                        key={group.id}
                        style={{ cursor: 'pointer', opacity: isFalsePositive ? 0.65 : 1 }}
                        onClick={() => navigate(`/issue-groups/${group.id}`)}
                      >
                        <td onClick={event => event.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selectedIds.includes(group.id)}
                            onChange={event => toggleSelected(group.id, event.target.checked)}
                            aria-label={`选择问题组 ${group.id}`}
                          />
                        </td>
                        <td style={{ color: '#888', fontSize: 13 }}>#{group.id}</td>
                        <td>{group.member_count}</td>
                        <td><span style={{ fontSize: 12 }}>{group.tool}</span></td>
                        <td style={{ fontFamily: 'monospace', fontSize: 13 }}>{group.rule_id || '-'}</td>
                        <td style={{ fontSize: 12, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {group.file_path ? `${group.file_path}:${group.line_start || '-'}` : '-'}
                        </td>
                        <td><SeverityBadge severity={isFalsePositive ? 'false_positive' : group.final_severity} /></td>
                        <td style={{ minWidth: 120 }}><RiskBar score={group.risk_score} /></td>
                        <td>{renderVerdict(group)}</td>
                        <td onClick={event => event.stopPropagation()}>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <button
                              className="btn btn-default"
                              style={{ fontSize: 12, padding: '2px 8px' }}
                              onClick={event => handleMarkIssueGroupFalsePositive(group, event)}
                            >
                              {group.is_false_positive ? '误报回退' : '标记误报'}
                            </button>
                            <button
                              className="btn btn-primary"
                              style={{ fontSize: 12, padding: '2px 8px' }}
                              onClick={event => handleAnalyzeIssueGroup(group, event)}
                            >
                              {group.analyzed_at === null ? '分析' : '重新分析'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  }) : findingData?.items.map(finding => {
                    const isFalsePositive = finding.is_false_positive || finding.is_vulnerable === false
                    return (
                      <tr
                        key={finding.id}
                        style={{ cursor: 'pointer', opacity: isFalsePositive ? 0.65 : 1 }}
                        onClick={() => navigate(`/findings/${finding.id}`)}
                      >
                        <td onClick={event => event.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selectedIds.includes(finding.id)}
                            onChange={event => toggleSelected(finding.id, event.target.checked)}
                            aria-label={`选择漏洞 ${finding.id}`}
                          />
                        </td>
                        <td style={{ color: '#888', fontSize: 13 }}>#{finding.id}</td>
                        <td><span style={{ fontSize: 12 }}>{finding.tool}</span></td>
                        <td style={{ fontFamily: 'monospace', fontSize: 13 }}>{finding.rule_id || '-'}</td>
                        <td style={{ fontSize: 12, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {finding.file_path ? `${finding.file_path}:${finding.line_start || '-'}` : '-'}
                        </td>
                        <td><SeverityBadge severity={isFalsePositive ? 'false_positive' : finding.final_severity} /></td>
                        <td style={{ minWidth: 120 }}><RiskBar score={finding.risk_score} /></td>
                        <td>{renderVerdict(finding)}</td>
                        <td onClick={event => event.stopPropagation()}>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <button
                              className="btn btn-default"
                              style={{ fontSize: 12, padding: '2px 8px' }}
                              onClick={event => handleMarkFindingFalsePositive(finding, event)}
                            >
                              {finding.is_false_positive ? '误报回退' : '标记误报'}
                            </button>
                            <button
                              className="btn btn-primary"
                              style={{ fontSize: 12, padding: '2px 8px' }}
                              onClick={event => handleAnalyzeFinding(finding, event)}
                            >
                              {finding.analyzed_at === null ? '分析' : '重新分析'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pagination">
            <button disabled={page <= 1} onClick={() => setPage(prev => prev - 1)}>上一页</button>
            <span style={{ fontSize: 14, color: '#666' }}>第 {page} / {totalPages} 页</span>
            <button disabled={page >= totalPages} onClick={() => setPage(prev => prev + 1)}>下一页</button>
          </div>
        </>
      )}
    </div>
  )
}
