import React, { useState } from 'react'
import apiService from '../services/api'

interface UploadTaskModalProps {
  onClose: () => void
  onSuccess: () => void
}

const TOOL_HINTS: Record<string, string> = {
  cppcheck: 'Cppcheck XML 输出 (cppcheck --xml ...)',
  coverity: 'Coverity JSON 导出格式',
  klocwork: 'Klocwork JSON 导出格式',
}

export default function UploadTaskModal({ onClose, onSuccess }: UploadTaskModalProps) {
  const [name, setName] = useState('')
  const [tool, setTool] = useState('cppcheck')
  const [rawInput, setRawInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !rawInput.trim()) {
      setError('请填写任务名称和扫描结果')
      return
    }
    setLoading(true)
    setError('')
    try {
      await apiService.createTask({ name, tool, raw_input: rawInput })
      onSuccess()
      onClose()
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || '上传失败'
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
    }}>
      <div style={{ background: 'white', borderRadius: 10, padding: 32, width: 560, maxWidth: '90vw' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600 }}>上传扫描结果</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: 20, cursor: 'pointer', color: '#666' }}>×</button>
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">任务名称 *</label>
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} placeholder="例如：2024-Q1 主模块扫描" />
          </div>
          <div className="form-group">
            <label className="form-label">SAST 工具 *</label>
            <select className="form-select" value={tool} onChange={e => setTool(e.target.value)}>
              <option value="cppcheck">Cppcheck</option>
              <option value="coverity">Coverity</option>
              <option value="klocwork">Klocwork</option>
            </select>
            <div style={{ fontSize: 12, color: '#888', marginTop: 4 }}>{TOOL_HINTS[tool]}</div>
          </div>
          <div className="form-group">
            <label className="form-label">扫描结果原始输出 *</label>
            <textarea
              className="form-textarea"
              value={rawInput}
              onChange={e => setRawInput(e.target.value)}
              placeholder="粘贴 SAST 工具的原始输出..."
              rows={8}
            />
          </div>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-default" onClick={onClose}>取消</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? '上传中...' : '上传分析'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
