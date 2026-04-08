import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import apiService, { AnalysisTarget, ScanTask } from '../services/api'
import UploadTaskModal from '../components/UploadTaskModal'
import { useProgress } from '../context/ProgressContext'

export default function TaskListPage() {
  const [tasks, setTasks] = useState<ScanTask[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [analyzingId, setAnalyzingId] = useState<number | null>(null)
  const [analysisTarget, setAnalysisTarget] = useState<AnalysisTarget>('issue_group')
  const navigate = useNavigate()
  const { openPanel } = useProgress()

  const load = async () => {
    setLoading(true)
    try {
      const r = await apiService.listTasks()
      setTasks(r.data)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleAnalyze = async (task: ScanTask) => {
    setAnalyzingId(task.id)
    try {
      await apiService.analyzeTask(task.id, { targetType: analysisTarget })
      openPanel(task.id)
    } catch {
      alert('提交分析失败，请检查服务是否正常运行')
    } finally {
      setAnalyzingId(null)
    }
  }

  const handleClearAll = async () => {
    if (!window.confirm('确定要清空所有任务和漏洞数据吗？此操作不可恢复。')) return
    try {
      await apiService.deleteAllTasks()
      await load()
    } catch {
      alert('清空失败，请重试')
    }
  }

  const toolColor: Record<string, string> = {
    cppcheck: '#1677ff',
    coverity: '#722ed1',
    klocwork: '#13c2c2',
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">扫描任务</h1>
        <div style={{ display: 'flex', gap: 10 }}>
          <select className="form-select" value={analysisTarget} onChange={e => setAnalysisTarget(e.target.value as AnalysisTarget)}>
            <option value="issue_group">分析对象: 问题组</option>
            <option value="finding">分析对象: 单条漏洞</option>
          </select>
          <button
            className="btn btn-default"
            style={{ color: '#ff4d4f', borderColor: '#ff4d4f' }}
            onClick={handleClearAll}
          >
            清空所有数据
          </button>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>+ 上传扫描结果</button>
        </div>
      </div>

      {loading ? (
        <div className="loading">加载中...</div>
      ) : tasks.length === 0 ? (
        <div className="empty-state">
          <div style={{ fontSize: 48, marginBottom: 16 }}>📋</div>
          <p>暂无扫描任务，点击右上角按钮上传扫描结果</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>任务名称</th>
                  <th>工具</th>
                  <th>状态</th>
                  <th>发现数量</th>
                  <th>归并后问题组</th>
                  <th>创建时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {tasks.map(task => (
                  <tr key={task.id}>
                    <td style={{ color: '#888', fontSize: 13 }}>#{task.id}</td>
                    <td>
                      <span
                        style={{ color: '#1677ff', cursor: 'pointer' }}
                        onClick={() => navigate(`/findings?task_id=${task.id}`)}
                      >
                        {task.name}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        background: toolColor[task.tool] || '#666',
                        color: 'white', padding: '2px 8px', borderRadius: 4, fontSize: 12
                      }}>
                        {task.tool}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${task.status === 'analyzed' ? 'badge-low' : 'badge-medium'}`}>
                        {task.status}
                      </span>
                    </td>
                    <td>{task.finding_count}</td>
                    <td>{task.issue_group_count}</td>
                    <td style={{ fontSize: 13, color: '#888' }}>
                      {new Date(task.created_at).toLocaleString('zh-CN')}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button
                          className="btn btn-default"
                          style={{ fontSize: 13, padding: '4px 10px' }}
                          onClick={() => navigate(`/findings?task_id=${task.id}`)}
                        >
                          查看漏洞
                        </button>
                        <button
                          className="btn btn-primary"
                          style={{ fontSize: 13, padding: '4px 10px' }}
                          onClick={() => handleAnalyze(task)}
                          disabled={analyzingId === task.id}
                        >
                          {analyzingId === task.id ? '提交中...' : analysisTarget === 'issue_group' ? '分析问题组' : '分析漏洞'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {showModal && (
        <UploadTaskModal
          onClose={() => setShowModal(false)}
          onSuccess={load}
        />
      )}
    </div>
  )
}
