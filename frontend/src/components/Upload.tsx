import { useCallback, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, UploadResult } from '../services/api'

const ACCEPTED = '.sarif,.json,.sarif.json'

export default function Upload() {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<UploadResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const handleFile = (f: File) => {
    setFile(f)
    setResult(null)
    setError(null)
  }

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }, [])

  const onInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) handleFile(f)
  }

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await api.upload(file)
      setResult(res)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 style={{ margin: '0 0 1.5rem', fontSize: '1.6rem', fontWeight: 700 }}>上传扫描报告</h1>

      <div className="card" style={{ maxWidth: 640 }}>
        <p style={{ margin: '0 0 1rem', color: '#555', fontSize: '.93rem' }}>
          支持格式：<strong>SARIF 2.1.0</strong>、<strong>Semgrep JSON</strong>、<strong>Bandit JSON</strong>、
          <strong>Checkov JSON</strong>、<strong>Trivy JSON</strong> 及其他通用 JSON 格式。
        </p>

        <form onSubmit={onSubmit}>
          <label
            className={`upload-area${dragging ? ' drag-over' : ''}`}
            onDragOver={e => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
          >
            <input type="file" accept={ACCEPTED} onChange={onInputChange} style={{ display: 'none' }} />
            <div className="upload-icon">📤</div>
            {file
              ? <div style={{ fontWeight: 600 }}>{file.name} <span style={{ color: '#888', fontWeight: 400 }}>({(file.size / 1024).toFixed(1)} KB)</span></div>
              : <div>点击选择文件，或将文件拖放到此处</div>
            }
            <div className="upload-hint">.sarif / .json 文件，最大 10 MB</div>
          </label>

          <div style={{ marginTop: '1rem' }}>
            <button className="btn btn-primary" type="submit" disabled={!file || loading} style={{ width: '100%', justifyContent: 'center' }}>
              {loading ? <><span className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} /> 上传中…</> : '上传并分析'}
            </button>
          </div>
        </form>

        {result && (
          <div className="alert alert-success" style={{ marginTop: '1rem' }}>
            <div style={{ fontWeight: 600, marginBottom: '.4rem' }}>✅ {result.message}</div>
            <div style={{ fontSize: '.9rem' }}>
              工具：{result.tool ?? '未知'} &nbsp;·&nbsp; 格式：{result.format.toUpperCase()} &nbsp;·&nbsp; 漏洞：{result.vulnerability_count} 个
            </div>
            <div style={{ marginTop: '.75rem', display: 'flex', gap: '.5rem' }}>
              <button className="btn btn-primary" onClick={() => navigate(`/reports/${result.report_id}`)}>
                查看报告
              </button>
              <button className="btn btn-outline" onClick={() => { setFile(null); setResult(null) }}>
                继续上传
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="alert alert-error" style={{ marginTop: '1rem' }}>
            ❌ 上传失败：{error}
          </div>
        )}
      </div>

      <div className="card" style={{ maxWidth: 640 }}>
        <div className="card-title">支持的工具列表</div>
        <table>
          <thead><tr><th>工具</th><th>格式</th><th>自动检测</th></tr></thead>
          <tbody>
            {[
              ['SARIF 2.1.0', '.sarif / .json', '✅'],
              ['Semgrep', '.json', '✅'],
              ['Bandit (Python)', '.json', '✅'],
              ['Checkov (IaC)', '.json', '✅'],
              ['Trivy', '.json', '✅'],
              ['通用 JSON', '.json', '自动回退'],
            ].map(([tool, fmt, auto]) => (
              <tr key={tool}>
                <td>{tool}</td>
                <td style={{ fontFamily: 'monospace', fontSize: '.88rem' }}>{fmt}</td>
                <td>{auto}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
