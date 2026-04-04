import React, { useEffect, useState } from 'react'
import apiService, { SystemSettings } from '../services/api'

type Tab = 'llm' | 'agent1' | 'agent2' | 'agent3' | 'agent4'

const TAB_LABELS: { key: Tab; label: string }[] = [
  { key: 'llm',    label: '大模型连接' },
  { key: 'agent1', label: 'Agent 1 代码理解' },
  { key: 'agent2', label: 'Agent 2 路径分析' },
  { key: 'agent3', label: 'Agent 3 漏洞判定' },
  { key: 'agent4', label: 'Agent 4 修复建议' },
]

const AGENT_PLACEHOLDERS: Record<string, { system: string; tmpl: string }> = {
  agent1: { system: 'agent1_system', tmpl: 'agent1_user_tmpl' },
  agent2: { system: 'agent2_system', tmpl: 'agent2_user_tmpl' },
  agent3: { system: 'agent3_system', tmpl: 'agent3_user_tmpl' },
  agent4: { system: 'agent4_system', tmpl: 'agent4_user_tmpl' },
}

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>('llm')
  const [form, setForm] = useState<SystemSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)

  const fetchSettings = () => {
    setLoading(true)
    apiService.getSettings()
      .then(r => setForm(r.data))
      .catch(() => setMsg({ type: 'err', text: '加载配置失败' }))
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchSettings() }, [])

  const set = (key: keyof SystemSettings, val: string) =>
    setForm(prev => prev ? { ...prev, [key]: val } : prev)

  const handleSave = async () => {
    if (!form) return
    setSaving(true)
    setMsg(null)
    try {
      const updated = await apiService.updateSettings(form)
      setForm(updated.data)
      setMsg({ type: 'ok', text: '✓ 保存成功，下次分析立即生效' })
    } catch (e: any) {
      setMsg({ type: 'err', text: e?.response?.data?.detail || '保存失败' })
    } finally {
      setSaving(false)
    }
  }

  const handleReset = async () => {
    if (!confirm('确认恢复所有配置为默认值？')) return
    setSaving(true)
    setMsg(null)
    try {
      const updated = await apiService.resetSettings()
      setForm(updated.data)
      setMsg({ type: 'ok', text: '✓ 已恢复默认配置' })
    } catch {
      setMsg({ type: 'err', text: '重置失败' })
    } finally {
      setSaving(false)
    }
  }

  if (loading || !form) return <div className="loading">加载中...</div>

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '8px 12px', border: '1px solid #d9d9d9',
    borderRadius: 6, fontSize: 14, boxSizing: 'border-box', fontFamily: 'inherit',
  }
  const textareaStyle: React.CSSProperties = {
    ...inputStyle, minHeight: 220, resize: 'vertical', fontFamily: 'monospace', fontSize: 13,
  }
  const labelStyle: React.CSSProperties = {
    display: 'block', marginBottom: 6, fontWeight: 500, fontSize: 14,
  }
  const groupStyle: React.CSSProperties = { marginBottom: 20 }
  const hintStyle: React.CSSProperties = { fontSize: 12, color: '#888', marginTop: 4 }

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1 className="page-title">系统配置</h1>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-default" onClick={handleReset} disabled={saving}>恢复默认</button>
          <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? '保存中...' : '保存配置'}
          </button>
        </div>
      </div>

      {msg && (
        <div style={{
          padding: '10px 16px', borderRadius: 6, marginBottom: 20,
          background: msg.type === 'ok' ? '#f6ffed' : '#fff2f0',
          border: `1px solid ${msg.type === 'ok' ? '#b7eb8f' : '#ffccc7'}`,
          color: msg.type === 'ok' ? '#389e0d' : '#cf1322',
        }}>
          {msg.text}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, borderBottom: '1px solid #f0f0f0', paddingBottom: 0 }}>
        {TAB_LABELS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            padding: '8px 18px', border: 'none', background: 'none', cursor: 'pointer',
            fontSize: 14, fontWeight: tab === t.key ? 600 : 400,
            borderBottom: tab === t.key ? '2px solid #1677ff' : '2px solid transparent',
            color: tab === t.key ? '#1677ff' : '#555',
          }}>{t.label}</button>
        ))}
      </div>

      <div style={{ maxWidth: 800 }}>

        {/* ── LLM 连接配置 ── */}
        {tab === 'llm' && (
          <div>
            <div style={groupStyle}>
              <label style={labelStyle}>API Key</label>
              <input style={inputStyle} type="password" value={form.llm_api_key}
                onChange={e => set('llm_api_key', e.target.value)}
                placeholder="sk-xxxxxxxx 或 ollama（本地模型）" />
              <div style={hintStyle}>保存后 Key 仅显示前8位，输入新值才会覆盖</div>
            </div>
            <div style={groupStyle}>
              <label style={labelStyle}>Model 名称</label>
              <input style={inputStyle} value={form.llm_model}
                onChange={e => set('llm_model', e.target.value)}
                placeholder="gpt-4o / gpt-4-turbo / llama3 / qwen2..." />
            </div>
            <div style={groupStyle}>
              <label style={labelStyle}>Base URL（自定义/本地模型，可留空）</label>
              <input style={inputStyle} value={form.llm_base_url}
                onChange={e => set('llm_base_url', e.target.value)}
                placeholder="http://localhost:11434/v1" />
              <div style={hintStyle}>兼容 OpenAI Chat Completions API 的端点均可使用（Ollama / vLLM / LM Studio 等）</div>
            </div>
            <div style={groupStyle}>
              <label style={labelStyle}>Temperature（0.0 - 1.0）</label>
              <input style={{ ...inputStyle, width: 120 }} value={form.llm_temperature}
                onChange={e => set('llm_temperature', e.target.value)}
                type="number" min="0" max="1" step="0.05" />
              <div style={hintStyle}>Agent 3（漏洞判定）固定使用 0.1，其他 Agent 使用此值</div>
            </div>
            <div style={groupStyle}>
              <label style={labelStyle}>源代码根目录</label>
              <input style={inputStyle} value={form.source_code_dir}
                onChange={e => set('source_code_dir', e.target.value)}
                placeholder="C:\projects\myapp（填入被分析项目的源码根目录，留空则跳过代码片段提取）" />
              <div style={hintStyle}>上传 SAST 报告时自动按此路径读取代码片段供 LLM 分析；留空则 LLM 仅凭报告描述分析（不影响已上传任务）</div>
            </div>
          </div>
        )}

        {/* ── Agent Prompt 编辑 ── */}
        {(['agent1', 'agent2', 'agent3', 'agent4'] as const).map(agentKey => {
          if (tab !== agentKey) return null
          const keys = AGENT_PLACEHOLDERS[agentKey]
          const agentNum = agentKey.replace('agent', '')
          const role = { '1': '代码理解分析师', '2': '执行路径分析专家', '3': '漏洞评估专家', '4': '安全编码顾问' }[agentNum]
          return (
            <div key={agentKey}>
              <div style={{ marginBottom: 16, padding: '10px 14px', background: '#f5f5f5', borderRadius: 6, fontSize: 13, color: '#555' }}>
                <strong>Agent {agentNum}</strong> — {role}。System Prompt 定义角色，User Prompt Template 填充具体 Finding 信息（使用 <code style={{ background: '#e6e6e6', padding: '1px 4px', borderRadius: 3 }}>{'{变量名}'}</code> 占位符）。
              </div>
              <div style={groupStyle}>
                <label style={labelStyle}>System Prompt</label>
                <textarea style={textareaStyle}
                  value={form[keys.system as keyof SystemSettings]}
                  onChange={e => set(keys.system as keyof SystemSettings, e.target.value)} />
              </div>
              <div style={groupStyle}>
                <label style={labelStyle}>User Prompt Template</label>
                <textarea style={{ ...textareaStyle, minHeight: 300 }}
                  value={form[keys.tmpl as keyof SystemSettings]}
                  onChange={e => set(keys.tmpl as keyof SystemSettings, e.target.value)} />
                <div style={hintStyle}>
                  可用占位符：
                  {agentKey === 'agent1' && ' {tool} {rule_id} {file_path} {line} {message} {function_name} {code_snippet}'}
                  {agentKey === 'agent2' && ' {tool} {rule_id} {message} {code_understanding} {execution_path} {code_snippet}'}
                  {agentKey === 'agent3' && ' {tool} {rule_id} {severity} {file_path} {line} {message} {code_understanding} {path_analysis}'}
                  {agentKey === 'agent4' && ' {tool} {rule_id} {file_path} {line} {message} {is_vulnerable} {confidence} {reason} {code_snippet}'}
                </div>
              </div>
            </div>
          )
        })}

      </div>
    </div>
  )
}
