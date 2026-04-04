import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, Report } from '../services/api'

function severityBadge(sev: string | null) {
  const s = (sev ?? 'info').toLowerCase()
  return <span className={`badge badge-${s}`}>{s}</span>
}

export default function ReportList() {
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<number | null>(null)
  const navigate = useNavigate()

  const load = () => {
    setLoading(true)
    api.listReports()
      .then(setReports)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const handleDelete = async (id: number) => {
    if (!confirm('确定要删除该报告吗？')) return
    setDeleting(id)
    try {
      await api.deleteReport(id)
      setReports(r => r.filter(x => x.id !== id))
    } catch (e: unknown) {
      alert('删除失败：' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setDeleting(null)
    }
  }

  if (loading) return <div style={{ textAlign: 'center', padding: '3rem' }}><div className="spinner" /></div>
  if (error) return <div className="alert alert-error">加载失败：{error}</div>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 700 }}>扫描报告</h1>
        <Link to="/upload"><button className="btn btn-primary">➕ 上传报告</button></Link>
      </div>

      {reports.length === 0 ? (
        <div className="card empty-state">
          <div className="empty-icon">📭</div>
          <div>暂无报告，<Link to="/upload" style={{ color: '#1a1a2e', fontWeight: 600 }}>上传第一份</Link>。</div>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>文件名</th>
                  <th>工具</th>
                  <th>格式</th>
                  <th>漏洞数</th>
                  <th>上传时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.id}>
                    <td style={{ color: '#999', fontSize: '.85rem' }}>{r.id}</td>
                    <td>
                      <Link to={`/reports/${r.id}`} style={{ color: '#1a1a2e', fontWeight: 500 }}>
                        {r.name}
                      </Link>
                    </td>
                    <td>{r.tool ?? <span style={{ color: '#bbb' }}>—</span>}</td>
                    <td><span style={{ textTransform: 'uppercase', fontSize: '.8rem', color: '#555' }}>{r.format}</span></td>
                    <td>
                      <strong style={{ color: r.vulnerability_count > 0 ? '#d32f2f' : '#388e3c' }}>
                        {r.vulnerability_count}
                      </strong>
                    </td>
                    <td style={{ fontSize: '.85rem', color: '#666' }}>
                      {new Date(r.created_at).toLocaleString('zh-CN')}
                    </td>
                    <td>
                      <button className="btn btn-danger" style={{ padding: '.3rem .7rem', fontSize: '.82rem' }}
                        disabled={deleting === r.id}
                        onClick={() => handleDelete(r.id)}>
                        {deleting === r.id ? '删除中…' : '删除'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
