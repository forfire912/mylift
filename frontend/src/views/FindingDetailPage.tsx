import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import apiService, { Finding } from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import RiskBar from '../components/RiskBar'
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import cpp from 'react-syntax-highlighter/dist/esm/languages/hljs/cpp'
import { vs2015 } from 'react-syntax-highlighter/dist/esm/styles/hljs'

SyntaxHighlighter.registerLanguage('cpp', cpp)

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await apiService.getFinding(parseInt(id!))
      setFinding(r.data)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [id])

  const handleAnalyze = async () => {
    setAnalyzing(true)
    try {
      await apiService.analyzeFinding(parseInt(id!))
      alert('已提交 LLM 分析，请稍后刷新查看结果')
    } finally {
      setAnalyzing(false)
    }
  }

  const handleMarkFP = async () => {
    if (!finding) return
    await apiService.markFalsePositive(finding.id, !finding.is_false_positive)
    load()
  }

  if (loading) return <div className="loading">加载中...</div>
  if (!finding) return <div className="empty-state">找不到该漏洞</div>

  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <button className="btn btn-default" onClick={() => navigate(-1)} style={{ marginRight: 12 }}>← 返回</button>
        <span style={{ color: '#888', fontSize: 14 }}>漏洞详情 #{finding.id}</span>
        {finding.issue_group_id && (
          <button className="btn btn-default" onClick={() => navigate(`/issue-groups/${finding.issue_group_id}`)} style={{ marginLeft: 12 }}>
            查看所属问题组
          </button>
        )}
      </div>

      {/* Header */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>
              {finding.rule_id}
              {finding.is_false_positive && (
                <span style={{ marginLeft: 8, fontSize: 12, color: '#52c41a', background: '#f6ffed', padding: '2px 8px', borderRadius: 4, border: '1px solid #b7eb8f' }}>
                  已标记为误报
                </span>
              )}
            </h2>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
              <span style={{ fontSize: 14, color: '#888' }}>工具: <strong style={{ color: '#333' }}>{finding.tool}</strong></span>
              <span style={{ fontSize: 14, color: '#888' }}>
                文件: <code style={{ background: '#f5f5f5', padding: '1px 6px', borderRadius: 3, fontSize: 13 }}>
                  {finding.file_path}:{finding.line_start}
                </code>
              </span>
              {finding.function_name && (
                <span style={{ fontSize: 14, color: '#888' }}>
                  函数: <code style={{ background: '#f5f5f5', padding: '1px 6px', borderRadius: 3, fontSize: 13 }}>{finding.function_name}</code>
                </span>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-default" onClick={handleMarkFP}>
              {finding.is_false_positive ? '误报回退' : '标记误报'}
            </button>
            {!finding.analyzed_at && (
              <button className="btn btn-primary" onClick={handleAnalyze} disabled={analyzing}>
                {analyzing ? '分析中...' : '🤖 LLM 分析'}
              </button>
            )}
          </div>
        </div>

        <div style={{ marginTop: 16, padding: '12px 16px', background: '#fffbe6', border: '1px solid #ffe58f', borderRadius: 6, fontSize: 14 }}>
          {finding.message}
        </div>
      </div>

      {/* Risk Info */}
      <div className="detail-grid">
        <div className="card">
          <h3 className="section-title">风险评估</h3>
          <table style={{ width: '100%', fontSize: 14 }}>
            <tbody>
              <tr>
                <td style={{ color: '#888', paddingBottom: 10, width: '40%' }}>SAST 严重性</td>
                <td><SeverityBadge severity={finding.sast_severity} /></td>
              </tr>
              <tr>
                <td style={{ color: '#888', paddingBottom: 10 }}>最终严重性</td>
                <td><SeverityBadge severity={finding.final_severity} /></td>
              </tr>
              <tr>
                <td style={{ color: '#888', paddingBottom: 10 }}>风险评分</td>
                <td><RiskBar score={finding.risk_score} /></td>
              </tr>
              {finding.llm_confidence !== null && (
                <tr>
                  <td style={{ color: '#888', paddingBottom: 10 }}>LLM 置信度</td>
                  <td>
                    <span className="confidence-badge">
                      {Math.round((finding.llm_confidence || 0) * 100)}%
                    </span>
                  </td>
                </tr>
              )}
              <tr>
                <td style={{ color: '#888' }}>LLM 判断</td>
                <td>
                  {finding.is_vulnerable === null ? (
                    <span style={{ color: '#bbb' }}>待分析</span>
                  ) : finding.is_vulnerable ? (
                    <span style={{ color: '#cf1322', fontWeight: 600 }}>⚠ 确认漏洞</span>
                  ) : (
                    <span style={{ color: '#52c41a', fontWeight: 600 }}>✓ 误报</span>
                  )}
                </td>
              </tr>
            </tbody>
          </table>
          {finding.analyzed_at && (
            <div style={{ fontSize: 12, color: '#bbb', marginTop: 8 }}>
              分析时间: {new Date(finding.analyzed_at).toLocaleString('zh-CN')}
            </div>
          )}
        </div>

        {/* Execution Path */}
        {finding.execution_path && finding.execution_path.length > 0 && (
          <div className="card">
            <h3 className="section-title">执行路径</h3>
            <div style={{ fontSize: 13 }}>
              {finding.execution_path.map((step, i) => (
                <div key={i} style={{
                  display: 'flex', gap: 10, padding: '6px 0',
                  borderBottom: i < finding.execution_path!.length - 1 ? '1px solid #f0f0f0' : 'none'
                }}>
                  <span style={{
                    background: '#1677ff', color: 'white', borderRadius: '50%',
                    width: 22, height: 22, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 11, flexShrink: 0
                  }}>{i + 1}</span>
                  <span style={{ color: '#555' }}>{step}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Code Snippet */}
      {finding.code_snippet && (
        <div className="card">
          <h3 className="section-title">代码片段</h3>
          <SyntaxHighlighter language="cpp" style={vs2015} customStyle={{ borderRadius: 6, fontSize: 13 }}>
            {finding.code_snippet}
          </SyntaxHighlighter>
        </div>
      )}

      {/* LLM Analysis */}
      {(finding.llm_code_understanding || finding.llm_path_analysis || finding.llm_reason) && (
        <div className="card">
          <h3 className="section-title">🤖 LLM 分析报告</h3>

          {finding.llm_code_understanding && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8, color: '#1677ff' }}>
                Agent 1 - 代码理解
              </div>
              <div style={{ fontSize: 14, lineHeight: 1.7, color: '#555', background: '#f8f9ff', padding: 16, borderRadius: 6 }}>
                {finding.llm_code_understanding}
              </div>
            </div>
          )}

          {finding.llm_path_analysis && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8, color: '#722ed1' }}>
                Agent 2 - 路径分析
              </div>
              <div style={{ fontSize: 14, lineHeight: 1.7, color: '#555', background: '#f9f0ff', padding: 16, borderRadius: 6 }}>
                {finding.llm_path_analysis}
              </div>
            </div>
          )}

          {finding.llm_reason && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8, color: '#cf1322' }}>
                Agent 3 - 漏洞判定理由
              </div>
              <div style={{ fontSize: 14, lineHeight: 1.7, color: '#555', background: '#fff0f0', padding: 16, borderRadius: 6 }}>
                {finding.llm_reason}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Fix Suggestion */}
      {finding.fix_suggestion && (
        <div className="card">
          <h3 className="section-title">🔧 Agent 4 - 修复建议</h3>
          <div style={{ fontSize: 14, lineHeight: 1.7, color: '#555', marginBottom: 16 }}>
            {finding.fix_suggestion}
          </div>
          {finding.patch_suggestion && (
            <div>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8, color: '#666' }}>建议补丁:</div>
              <SyntaxHighlighter language="cpp" style={vs2015} customStyle={{ borderRadius: 6, fontSize: 13 }}>
                {finding.patch_suggestion}
              </SyntaxHighlighter>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
