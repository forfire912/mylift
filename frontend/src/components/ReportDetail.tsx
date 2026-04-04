import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api, ReportDetail as ReportDetailType, Vulnerability } from '../services/api'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

function Badge({ sev }: { sev: string | null }) {
  const s = (sev ?? 'info').toLowerCase()
  return <span className={`badge badge-${s}`}>{s}</span>
}

function VulnRow({ v }: { v: Vulnerability }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <tr style={{ cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
        <td>{v.id}</td>
        <td><Badge sev={v.severity} /></td>
        <td style={{ fontFamily: 'monospace', fontSize: '.88rem' }}>{v.rule_id ?? '—'}</td>
        <td style={{ maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {v.message ?? '—'}
        </td>
        <td style={{ fontSize: '.85rem', color: '#555' }}>
          {v.file_path ? (
            <span>{v.file_path}{v.start_line ? `:${v.start_line}` : ''}</span>
          ) : '—'}
        </td>
        <td style={{ fontSize: '.82rem', color: '#888' }}>{v.cwe ?? '—'}</td>
        <td style={{ fontSize: '1.1rem', color: '#999' }}>{open ? '▲' : '▼'}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} style={{ background: '#f8f9fa', padding: '1rem 1.5rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '.9rem' }}>
              <div><strong>规则 ID：</strong> {v.rule_id ?? '—'}</div>
              <div><strong>严重程度：</strong> {v.severity ?? '—'}</div>
              <div><strong>文件路径：</strong> {v.file_path ?? '—'}</div>
              <div><strong>行号：</strong> {v.start_line ?? '—'}{v.end_line && v.end_line !== v.start_line ? `–${v.end_line}` : ''}</div>
              <div><strong>CWE：</strong> {v.cwe ?? '—'}</div>
              <div><strong>标签：</strong> {v.tags ?? '—'}</div>
              {v.message && <div style={{ gridColumn: '1/-1' }}><strong>详情：</strong> {v.message}</div>}
            </div>
            {v.code_snippet && (
              <div>
                <div style={{ fontWeight: 600, fontSize: '.88rem', marginTop: '.75rem', marginBottom: '.3rem' }}>代码片段</div>
                <div className="code-block">{v.code_snippet}</div>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>()
  const [report, setReport] = useState<ReportDetailType | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filterSev, setFilterSev] = useState('')
  const [search, setSearch] = useState('')

  useEffect(() => {
    if (!id) return
    api.getReport(Number(id))
      .then(setReport)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div style={{ textAlign: 'center', padding: '3rem' }}><div className="spinner" /></div>
  if (error) return <div className="alert alert-error">加载失败：{error}</div>
  if (!report) return null

  const filtered = report.vulnerabilities
    .filter(v => !filterSev || v.severity === filterSev)
    .filter(v => !search || [v.rule_id, v.message, v.file_path].some(f => f?.toLowerCase().includes(search.toLowerCase())))

  const sevCounts = report.vulnerabilities.reduce<Record<string, number>>((acc, v) => {
    const k = v.severity ?? 'unknown'
    acc[k] = (acc[k] ?? 0) + 1
    return acc
  }, {})

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <Link to="/reports" style={{ color: '#666', fontSize: '.9rem' }}>← 返回报告列表</Link>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1 style={{ margin: '0 0 .5rem', fontSize: '1.4rem', fontWeight: 700 }}>{report.name}</h1>
            <div style={{ display: 'flex', gap: '1.5rem', fontSize: '.9rem', color: '#555' }}>
              <span><strong>工具：</strong>{report.tool ?? '未知'}</span>
              <span><strong>格式：</strong>{report.format.toUpperCase()}</span>
              <span><strong>上传：</strong>{new Date(report.created_at).toLocaleString('zh-CN')}</span>
              <span><strong>漏洞总数：</strong><span style={{ color: '#d32f2f', fontWeight: 600 }}>{report.vulnerability_count}</span></span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '.75rem', flexWrap: 'wrap', marginTop: '1rem' }}>
          {SEV_ORDER.filter(s => sevCounts[s]).map(s => (
            <span key={s} className={`badge badge-${s}`} style={{ fontSize: '.85rem' }}>
              {s}: {sevCounts[s]}
            </span>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-title">漏洞列表 ({filtered.length} / {report.vulnerability_count})</div>

        <div className="filters">
          <select value={filterSev} onChange={e => setFilterSev(e.target.value)}>
            <option value="">全部严重程度</option>
            {SEV_ORDER.filter(s => sevCounts[s]).map(s => (
              <option key={s} value={s}>{s} ({sevCounts[s]})</option>
            ))}
          </select>
          <input type="text" placeholder="搜索规则/描述/文件…" value={search} onChange={e => setSearch(e.target.value)} style={{ minWidth: 220 }} />
          {(filterSev || search) && (
            <button className="btn btn-outline" onClick={() => { setFilterSev(''); setSearch('') }}>清除筛选</button>
          )}
        </div>

        {filtered.length === 0 ? (
          <div className="empty-state"><div className="empty-icon">✅</div><div>没有匹配的漏洞。</div></div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>严重程度</th>
                  <th>规则 ID</th>
                  <th>描述</th>
                  <th>位置</th>
                  <th>CWE</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(v => <VulnRow key={v.id} v={v} />)}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
