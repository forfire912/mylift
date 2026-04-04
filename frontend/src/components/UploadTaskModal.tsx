import React, { useRef, useState } from 'react'
import apiService from '../services/api'

interface UploadTaskModalProps {
  onClose: () => void
  onSuccess: () => void
}

const TOOL_INFO: Record<string, { label: string; ext: string; hint: string }> = {
  cppcheck:  { label: 'Cppcheck',  ext: '.xml',  hint: 'cppcheck --xml --xml-version=2 ... 2> result.xml' },
  coverity:  { label: 'Coverity',  ext: '.json', hint: 'Coverity JSON 导出（issues.json）' },
  klocwork:  { label: 'Klocwork',  ext: '.json', hint: 'Klocwork JSON 报告文件' },
}

export default function UploadTaskModal({ onClose, onSuccess }: UploadTaskModalProps) {
  const [name, setName] = useState('')
  const [tool, setTool] = useState('cppcheck')
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) { setError('请填写任务名称'); return }
    if (!file) { setError('请选择报告文件'); return }
    setLoading(true)
    setError('')
    try {
      await apiService.createTask({ name, tool, file })
      onSuccess()
      onClose()
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || '上传失败'
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg))
    } finally {
      setLoading(false)
    }
  }

  const info = TOOL_INFO[tool]

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
    }}>
      <div style={{ background: 'white', borderRadius: 10, padding: 32, width: 520, maxWidth: '90vw' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600 }}>新建扫描任务</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: 20, cursor: 'pointer', color: '#666' }}>×</button>
        </div>

        {error && <div className="alert alert-error" style={{ marginBottom: 16 }}>{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">任务名称 *</label>
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="例如：2024-Q1 主模块扫描" />
          </div>

          <div className="form-group">
            <label className="form-label">SAST 工具 *</label>
            <select className="form-select" value={tool} onChange={e => { setTool(e.target.value); setFile(null); if (fileRef.current) fileRef.current.value = '' }}>
              {Object.entries(TOOL_INFO).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
            <div style={{ fontSize: 12, color: '#888', marginTop: 4 }}>{info.hint}</div>
          </div>

          <div className="form-group">
            <label className="form-label">报告文件 * <span style={{ color: '#888', fontWeight: 400 }}>（{info.ext}）</span></label>
            <input
              ref={fileRef}
              type="file"
              accept={info.ext}
              className="form-input"
              style={{ padding: '6px 10px', cursor: 'pointer' }}
              onChange={e => {
                const f = e.target.files?.[0] ?? null
                setFile(f)
                // 若名称尚未填写，用文件名（去掉扩展名）自动填充
                if (f && !name.trim()) {
                  setName(f.name.replace(/\.[^/.]+$/, ''))
                }
              }}
            />
            {file && (
              <div style={{ fontSize: 12, color: '#52c41a', marginTop: 4 }}>
                已选择：{file.name}（{(file.size / 1024).toFixed(1)} KB）
              </div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end', marginTop: 8 }}>
            <button type="button" className="btn btn-default" onClick={onClose}>取消</button>
            <button type="submit" className="btn btn-primary" disabled={loading || !file || !name.trim()}>
              {loading ? '上传中...' : '上传并解析'}
            </button>
          </div>
          {(!name.trim() || !file) && (
            <div style={{ textAlign: 'right', fontSize: 12, color: '#aaa', marginTop: 6 }}>
              {!file ? '请先选择报告文件' : '请填写任务名称'}
            </div>
          )}
        </form>
      </div>
    </div>
  )
}
