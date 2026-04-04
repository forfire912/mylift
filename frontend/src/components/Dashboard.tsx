import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ReportStats } from '../services/api'

function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const colors: Record<string, string> = {
    critical: '#7c0000', high: '#d32f2f', medium: '#f57c00', low: '#388e3c', info: '#1976d2',
  }
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (total === 0) return <div style={{ color: '#999', fontSize: '.9rem' }}>暂无数据</div>
  return (
    <div>
      <div style={{ display: 'flex', height: 20, borderRadius: 4, overflow: 'hidden', marginBottom: '.75rem' }}>
        {order.map(sev => {
          const n = counts[sev] ?? 0
          if (!n) return null
          return (
            <div key={sev} title={`${sev}: ${n}`}
              style={{ width: `${(n / total) * 100}%`, background: colors[sev] ?? '#999' }} />
          )
        })}
      </div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '.88rem' }}>
        {order.map(sev => {
          const n = counts[sev] ?? 0
          if (!n) return null
          return (
            <span key={sev} style={{ color: colors[sev] ?? '#999' }}>
              ● {sev}: <strong>{n}</strong>
            </span>
          )
        })}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<ReportStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.stats()
      .then(setStats)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div style={{ textAlign: 'center', padding: '3rem' }}><div className="spinner" /></div>
  if (error) return <div className="alert alert-error">加载失败：{error}</div>
  if (!stats) return null

  return (
    <div>
      <h1 style={{ margin: '0 0 1.5rem', fontSize: '1.6rem', fontWeight: 700 }}>总览</h1>

      <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
        <div className="stat-card">
          <div className="stat-number" style={{ color: '#1a1a2e' }}>{stats.total_reports}</div>
          <div className="stat-label">扫描报告</div>
        </div>
        <div className="stat-card">
          <div className="stat-number" style={{ color: '#d32f2f' }}>{stats.total_vulnerabilities}</div>
          <div className="stat-label">漏洞总数</div>
        </div>
        {Object.entries(stats.by_severity).sort().map(([sev, n]) => (
          <div key={sev} className="stat-card">
            <div className={`stat-number sev-${sev}`}>{n}</div>
            <div className="stat-label">{sev}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div className="card">
          <div className="card-title">按严重程度分布</div>
          <SeverityBar counts={stats.by_severity} />
        </div>

        <div className="card">
          <div className="card-title">按工具分布</div>
          {Object.keys(stats.by_tool).length === 0
            ? <div style={{ color: '#999', fontSize: '.9rem' }}>暂无数据</div>
            : (
              <table>
                <thead><tr><th>工具</th><th>报告数</th></tr></thead>
                <tbody>
                  {Object.entries(stats.by_tool).map(([tool, n]) => (
                    <tr key={tool}><td>{tool}</td><td>{n}</td></tr>
                  ))}
                </tbody>
              </table>
            )}
        </div>
      </div>

      {stats.total_reports === 0 && (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: '.5rem' }}>📂</div>
          <div style={{ color: '#666', marginBottom: '1rem' }}>还没有扫描报告，上传第一份报告开始分析。</div>
          <Link to="/upload"><button className="btn btn-primary">立即上传</button></Link>
        </div>
      )}
    </div>
  )
}
