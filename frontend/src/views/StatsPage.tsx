import React, { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import apiService, { AnalysisTarget, Stats } from '../services/api'
import {
  PieChart, Pie, Cell, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer,
} from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4d4f',
  high: '#fa8c16',
  medium: '#faad14',
  low: '#52c41a',
  info: '#1677ff',
  unknown: '#8c8c8c',
}

export default function StatsPage() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)
  const [searchParams] = useSearchParams()
  const taskId = searchParams.get('task_id') ? parseInt(searchParams.get('task_id')!) : undefined
  const [scope, setScope] = useState<AnalysisTarget>((searchParams.get('scope') as AnalysisTarget) || 'issue_group')

  useEffect(() => {
    setLoading(true)
    apiService.getStats(taskId, scope).then(r => setStats(r.data)).finally(() => setLoading(false))
  }, [scope, taskId])

  if (loading) return <div className="loading">加载中...</div>
  if (!stats) return <div className="empty-state">暂无统计数据</div>

  const severityData = Object.entries(stats.severity_distribution).map(([k, v]) => ({
    name: k,
    value: v,
    fill: SEVERITY_COLORS[k] || '#8c8c8c',
  }))

  const toolData = Object.entries(stats.tool_distribution).map(([k, v]) => ({
    name: k,
    count: v,
  }))

  const analysisData = [
    { name: '已分析', value: stats.analyzed_findings },
    { name: '待分析', value: stats.total_findings - stats.analyzed_findings },
  ]

  const verdictData = [
    { name: '确认漏洞', value: stats.vulnerable_findings },
    { name: '误报', value: stats.false_positive_findings },
    { name: '未判定', value: stats.analyzed_findings - stats.vulnerable_findings - stats.false_positive_findings },
  ]

  const unitLabel = scope === 'issue_group' ? '问题组' : '漏洞'

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">统计分析</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className={scope === 'issue_group' ? 'btn btn-primary' : 'btn btn-default'} onClick={() => setScope('issue_group')}>
            问题组视图
          </button>
          <button className={scope === 'finding' ? 'btn btn-primary' : 'btn btn-default'} onClick={() => setScope('finding')}>
            原始漏洞视图
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.total_findings}</div>
          <div className="stat-label">总{unitLabel}数</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#52c41a' }}>{stats.analyzed_findings}</div>
          <div className="stat-label">已分析</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#cf1322' }}>{stats.vulnerable_findings}</div>
          <div className="stat-label">确认漏洞</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#13c2c2' }}>{stats.false_positive_rate}%</div>
          <div className="stat-label">误报率</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: '#fa8c16' }}>{stats.avg_risk_score}</div>
          <div className="stat-label">平均风险分</div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="detail-grid">
        {/* Severity Distribution Pie */}
        <div className="card">
          <h3 className="section-title">严重性分布</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: 40 }}>暂无数据</div>
          )}
        </div>

        {/* Tool Distribution Bar */}
        <div className="card">
          <h3 className="section-title">工具来源分布</h3>
          {toolData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={toolData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#1677ff" name={`${unitLabel}数`} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: 40 }}>暂无数据</div>
          )}
        </div>

        {/* Analysis Progress */}
        <div className="card">
          <h3 className="section-title">分析进度</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={analysisData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
                <Cell fill="#52c41a" />
                <Cell fill="#d9d9d9" />
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* LLM Verdict */}
        <div className="card">
          <h3 className="section-title">LLM 判定结果</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={verdictData.filter(d => d.value > 0)} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
                <Cell fill="#cf1322" />
                <Cell fill="#52c41a" />
                <Cell fill="#d9d9d9" />
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Summary */}
      <div className="card">
        <h3 className="section-title">分析摘要</h3>
        <div style={{ fontSize: 14, lineHeight: 2, color: '#555' }}>
          <p>✅ 共统计 <strong>{stats.total_findings}</strong> 个{unitLabel}，已完成 LLM 分析 <strong>{stats.analyzed_findings}</strong> 个。</p>
          <p>⚠️ 确认为真实漏洞: <strong style={{ color: '#cf1322' }}>{stats.vulnerable_findings}</strong> 个，
            误报: <strong style={{ color: '#52c41a' }}>{stats.false_positive_findings}</strong> 个。</p>
          <p>📊 LLM 辅助误报率: <strong style={{ color: '#1677ff' }}>{stats.false_positive_rate}%</strong>，
            平均风险评分: <strong style={{ color: '#fa8c16' }}>{stats.avg_risk_score}</strong>。</p>
        </div>
      </div>
    </div>
  )
}
