import React, { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import apiService, { Finding, IssueGroup } from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import RiskBar from '../components/RiskBar'
import { useProgress } from '../context/ProgressContext'

export default function IssueGroupDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { openPanel } = useProgress()
  const [issueGroup, setIssueGroup] = useState<IssueGroup | null>(null)
  const [members, setMembers] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)

  const load = async () => {
    if (!id) return
    setLoading(true)
    try {
      const groupResponse = await apiService.getIssueGroup(parseInt(id, 10))
      setIssueGroup(groupResponse.data)
      setMembers(groupResponse.data.member_findings || [])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [id])

  const handleAnalyze = async () => {
    if (!issueGroup) return
    setSubmitting(true)
    try {
      await apiService.analyzeIssueGroup(issueGroup.id)
      openPanel(issueGroup.task_id)
      alert('已提交问题组 LLM 分析，请稍后刷新查看结果')
    } finally {
      setSubmitting(false)
    }
  }

  const handleToggleFalsePositive = async () => {
    if (!issueGroup) return
    setSubmitting(true)
    try {
      await apiService.markIssueGroupFalsePositive(issueGroup.id, !issueGroup.is_false_positive)
      await load()
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) return <div className="loading">加载中...</div>
  if (!issueGroup) return <div className="empty-state">找不到该问题组</div>

  const isFalsePositive = issueGroup.is_false_positive || issueGroup.is_vulnerable === false

  return (
    <div>
      <div style={{ marginBottom: 20, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <button className="btn btn-default" onClick={() => navigate(-1)}>← 返回</button>
        <span style={{ color: '#888', fontSize: 14 }}>问题组详情 #{issueGroup.id}</span>
        <span style={{ color: '#888', fontSize: 14 }}>任务 #{issueGroup.task_id}</span>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>{issueGroup.rule_id || '未命名规则'}</h2>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', color: '#666', fontSize: 14 }}>
              <span>工具: <strong style={{ color: '#333' }}>{issueGroup.tool}</strong></span>
              <span>成员数: <strong style={{ color: '#333' }}>{issueGroup.member_count}</strong></span>
              <span>位置: <strong style={{ color: '#333' }}>{issueGroup.file_path || '-'}</strong>{issueGroup.line_start ? `:${issueGroup.line_start}` : ''}</span>
              {issueGroup.function_name && <span>函数: <strong style={{ color: '#333' }}>{issueGroup.function_name}</strong></span>}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn btn-default" onClick={handleToggleFalsePositive} disabled={submitting}>
              {issueGroup.is_false_positive ? '误报回退' : '标记误报'}
            </button>
            <button className="btn btn-primary" onClick={handleAnalyze} disabled={submitting}>
              {submitting ? '提交中...' : issueGroup.analyzed_at ? '重新分析' : 'LLM 分析'}
            </button>
            {issueGroup.representative_finding_id && (
              <button className="btn btn-default" onClick={() => navigate(`/findings/${issueGroup.representative_finding_id}`)}>
                查看代表漏洞
              </button>
            )}
          </div>
        </div>

        <div style={{ marginTop: 16, padding: '12px 16px', background: '#fafafa', borderRadius: 6, border: '1px solid #f0f0f0', lineHeight: 1.7 }}>
          {issueGroup.message || '暂无问题描述'}
        </div>
      </div>

      <div className="detail-grid">
        <div className="card">
          <h3 className="section-title">组级判定</h3>
          <table style={{ width: '100%', fontSize: 14 }}>
            <tbody>
              <tr>
                <td style={{ color: '#888', paddingBottom: 10, width: '40%' }}>最终严重性</td>
                <td><SeverityBadge severity={isFalsePositive ? 'false_positive' : issueGroup.final_severity} /></td>
              </tr>
              <tr>
                <td style={{ color: '#888', paddingBottom: 10 }}>风险评分</td>
                <td><RiskBar score={issueGroup.risk_score} /></td>
              </tr>
              <tr>
                <td style={{ color: '#888', paddingBottom: 10 }}>LLM 判断</td>
                <td>
                  {issueGroup.is_vulnerable === null ? '待分析' : issueGroup.is_vulnerable ? '确认漏洞' : '误报'}
                </td>
              </tr>
              <tr>
                <td style={{ color: '#888', paddingBottom: 10 }}>LLM 置信度</td>
                <td>{issueGroup.llm_confidence !== null ? `${Math.round(issueGroup.llm_confidence * 100)}%` : '-'}</td>
              </tr>
              <tr>
                <td style={{ color: '#888' }}>误报状态</td>
                <td>{issueGroup.is_false_positive ? '已标记误报' : '未标记'}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="card">
          <h3 className="section-title">组内成员</h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {members.map(member => (
              <button
                key={member.id}
                className="btn btn-default"
                style={{ padding: '4px 10px', fontSize: 12 }}
                onClick={() => navigate(`/findings/${member.id}`)}
              >
                #{member.id}{member.is_representative ? ' 代表项' : ''}
              </button>
            ))}
          </div>
        </div>
      </div>

      {(issueGroup.llm_reason || issueGroup.llm_code_understanding || issueGroup.llm_path_analysis) && (
        <div className="card">
          <h3 className="section-title">LLM 归并分析</h3>
          {issueGroup.llm_code_understanding && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>代码理解</div>
              <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.7, color: '#555' }}>{issueGroup.llm_code_understanding}</div>
            </div>
          )}
          {issueGroup.llm_path_analysis && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>路径分析</div>
              <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.7, color: '#555' }}>{issueGroup.llm_path_analysis}</div>
            </div>
          )}
          {issueGroup.llm_reason && (
            <div>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>判定理由</div>
              <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.7, color: '#555' }}>{issueGroup.llm_reason}</div>
            </div>
          )}
        </div>
      )}

      {members.length > 0 && (
        <div className="card">
          <h3 className="section-title">成员明细</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>位置</th>
                  <th>最终严重性</th>
                  <th>风险评分</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {members.map(member => {
                  const memberFalsePositive = member.is_false_positive || member.is_vulnerable === false
                  return (
                    <tr key={member.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/findings/${member.id}`)}>
                      <td>#{member.id}{member.is_representative ? ' (代表项)' : ''}</td>
                      <td>{member.file_path || '-'}{member.line_start ? `:${member.line_start}` : ''}</td>
                      <td><SeverityBadge severity={memberFalsePositive ? 'false_positive' : member.final_severity} /></td>
                      <td><RiskBar score={member.risk_score} /></td>
                      <td>{member.is_vulnerable === null ? '待分析' : member.is_vulnerable ? '确认漏洞' : '误报'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}