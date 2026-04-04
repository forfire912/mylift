import React, { useEffect, useRef, useState } from 'react'
import apiService, { TaskProgress, AgentInfo } from '../services/api'
import { useProgress } from '../context/ProgressContext'

const POLL_INTERVAL = 1500 // ms

const STATUS_COLOR: Record<string, string> = {
  pending: '#bbb',
  running: '#1677ff',
  done:    '#52c41a',
  error:   '#ff4d4f',
}
const STATUS_ICON: Record<string, string> = {
  pending: '○',
  running: '⟳',
  done:    '✓',
  error:   '✗',
}
const STATUS_LABEL_ZH: Record<string, string> = {
  pending:     '等待中',
  running:     '运行中',
  done:        '完成',
  error:       '出错',
  not_started: '未开始',
}

function AgentCard({ num, info }: { num: string; info: AgentInfo }) {
  const [expanded, setExpanded] = useState(false)
  const color = STATUS_COLOR[info.status]
  const icon = STATUS_ICON[info.status]
  const isRunning = info.status === 'running'

  return (
    <div style={{
      border: `1px solid ${isRunning ? '#1677ff' : '#f0f0f0'}`,
      borderRadius: 8,
      marginBottom: 10,
      background: isRunning ? '#f0f7ff' : '#fff',
      transition: 'all 0.2s',
      boxShadow: isRunning ? '0 0 0 2px rgba(22,119,255,0.15)' : 'none',
    }}>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', cursor: info.output ? 'pointer' : 'default' }}
        onClick={() => info.output && setExpanded(e => !e)}
      >
        <span style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 28, height: 28, borderRadius: 6,
          background: `${color}22`, color, fontWeight: 700, fontSize: 15,
          animation: isRunning ? 'spin 1.2s linear infinite' : 'none',
        }}>
          {isRunning ? '⟳' : icon}
        </span>
        <div style={{ flex: 1 }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>Agent {num}</span>
          <span style={{ color: '#888', fontSize: 12, marginLeft: 6 }}>{info.label}</span>
        </div>
        <span style={{
          fontSize: 11, fontWeight: 600, color,
          background: `${color}18`, padding: '2px 8px', borderRadius: 12,
        }}>
          {STATUS_LABEL_ZH[info.status] || info.status}
        </span>
        {info.output && (
          <span style={{ color: '#bbb', fontSize: 11 }}>{expanded ? '▲' : '▼'}</span>
        )}
      </div>
      {expanded && info.output && (
        <div style={{
          padding: '0 14px 12px',
          fontSize: 12, fontFamily: 'monospace', color: '#555',
          whiteSpace: 'pre-wrap', wordBreak: 'break-word',
          maxHeight: 250, overflowY: 'auto',
          borderTop: '1px solid #f0f0f0', paddingTop: 10,
        }}>
          {info.output}
        </div>
      )}
    </div>
  )
}

export default function AgentProgressPanel() {
  const { activeTaskId, openPanel } = useProgress()
  const [progress, setProgress] = useState<TaskProgress | null>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Auto-load latest task on mount when no active task is set
  useEffect(() => {
    if (!activeTaskId) {
      apiService.listTasks().then(r => {
        const tasks = r.data
        if (tasks.length > 0) openPanel(tasks[tasks.length - 1].id)
      }).catch(() => {})
    }
  }, [])

  const fetchProgress = async (taskId: number) => {
    try {
      const r = await apiService.getTaskProgress(taskId)
      setProgress(r.data)
      if (r.data.status === 'done' || r.data.status === 'error') {
        if (timerRef.current) clearInterval(timerRef.current)
      }
    } catch { /* ignore */ }
  }

  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current)
    if (activeTaskId) {
      setProgress(null)
      fetchProgress(activeTaskId)
      timerRef.current = setInterval(() => fetchProgress(activeTaskId), POLL_INTERVAL)
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [activeTaskId])

  const overallStatus = progress?.status ?? 'not_started'
  const pct = progress && progress.finding_total > 0
    ? Math.round((progress.finding_current / progress.finding_total) * 100)
    : 0

  return (
    <>
      {/* Panel - always visible */}
      <div style={{
        position: 'fixed', top: 56, right: 0, bottom: 0,
        width: 420, zIndex: 1100,
        background: '#fff', border: 'none',
        borderLeft: '1px solid #e8e8e8',
        boxShadow: '-4px 0 24px rgba(0,0,0,0.10)',
        display: 'flex', flexDirection: 'column',
      }}>
        {/* Header */}
        <div style={{
          padding: '16px 20px', borderBottom: '1px solid #f0f0f0',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          background: '#fafafa',
        }}>
          <div>
            <span style={{ fontWeight: 700, fontSize: 15 }}>Agent 分析进度</span>
            {activeTaskId && (
              <span style={{ marginLeft: 8, color: '#888', fontSize: 12 }}>任务 #{activeTaskId}</span>
            )}
          </div>
        </div>

        {/* Overall status bar */}
        <div style={{ padding: '14px 20px', borderBottom: '1px solid #f5f5f5' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 13 }}>
            <span style={{ color: STATUS_COLOR[overallStatus] || '#bbb', fontWeight: 600 }}>
              {overallStatus === 'running' && '● 分析中...'}
              {overallStatus === 'done' && '✓ 分析完成'}
              {overallStatus === 'error' && '✗ 分析出错'}
              {(overallStatus === 'not_started' || overallStatus === 'pending') && '○ 等待中'}
            </span>
            {progress && (
              <span style={{ color: '#888' }}>
                {progress.finding_current} / {progress.finding_total} 个漏洞
              </span>
            )}
          </div>
          <div style={{ height: 6, background: '#f0f0f0', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 3,
              width: `${overallStatus === 'done' ? 100 : pct}%`,
              background: overallStatus === 'error' ? '#ff4d4f' : '#1677ff',
              transition: 'width 0.4s',
            }} />
          </div>
        </div>

        {/* Agent cards */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          {!progress || !progress.agents || Object.keys(progress.agents).length === 0 ? (
            <div style={{ textAlign: 'center', color: '#bbb', paddingTop: 60 }}>
              <div style={{ fontSize: 32, marginBottom: 10 }}>⟳</div>
              <div>等待分析启动...</div>
            </div>
          ) : (
            Object.entries(progress.agents).map(([num, info]) => (
              <AgentCard key={num} num={num} info={info} />
            ))
          )}
        </div>

        {/* Footer hint */}
        <div style={{
          padding: '12px 20px', borderTop: '1px solid #f0f0f0',
          fontSize: 12, color: '#aaa', textAlign: 'center',
        }}>
          {progress?.status === 'running' ? '每 1.5 秒自动刷新 · 点击 Agent 卡片查看输出' : '点击 Agent 卡片展开输出内容'}
        </div>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </>
  )
}
