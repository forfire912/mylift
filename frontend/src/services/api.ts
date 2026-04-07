import axios from 'axios'

const axiosClient = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

export interface ScanTask {
  id: number
  name: string
  tool: string
  status: string
  created_at: string
  updated_at: string
  finding_count: number
}

export interface Finding {
  id: number
  task_id: number
  rule_id: string | null
  tool: string
  file_path: string | null
  line_start: number | null
  line_end: number | null
  message: string | null
  sast_severity: string | null
  code_snippet: string | null
  function_name: string | null
  execution_path: string[] | null
  llm_code_understanding: string | null
  llm_path_analysis: string | null
  is_vulnerable: boolean | null
  llm_confidence: number | null
  llm_reason: string | null
  fix_suggestion: string | null
  patch_suggestion: string | null
  risk_score: number | null
  final_severity: string | null
  is_false_positive: boolean
  created_at: string
  analyzed_at: string | null
}

export interface FindingListResponse {
  total: number
  items: Finding[]
}

export interface Stats {
  total_findings: number
  analyzed_findings: number
  vulnerable_findings: number
  false_positive_findings: number
  false_positive_rate: number
  severity_distribution: Record<string, number>
  tool_distribution: Record<string, number>
  avg_risk_score: number
}

export interface AgentInfo {
  label: string
  status: 'pending' | 'running' | 'done' | 'error'
  output: string
  started_at: string | null
  finished_at: string | null
}

export interface TaskProgress {
  task_id: number
  status: 'running' | 'done' | 'error' | 'not_started' | 'pending'
  finding_total: number
  finding_current: number
  current_agent: number
  started_at: string | null
  finished_at: string | null
  agents: Record<string, AgentInfo>
}

export interface SystemSettings {
  llm_api_key: string
  llm_model: string
  llm_base_url: string
  llm_temperature: string
  source_code_dir: string
  agent1_system: string
  agent2_system: string
  agent3_system: string
  agent4_system: string
  agent1_user_tmpl: string
  agent2_user_tmpl: string
  agent3_user_tmpl: string
  agent4_user_tmpl: string
}

export const apiService = {
  // Tasks - 读取文件内容后以 JSON body 提交
  createTask: async (data: { name: string; tool: string; file: File }) => {
    const raw_input = await data.file.text()
    return axiosClient.post<ScanTask>('/tasks', {
      name: data.name,
      tool: data.tool,
      raw_input,
    })
  },
  listTasks: () => axiosClient.get<ScanTask[]>('/tasks'),
  getTask: (id: number) => axiosClient.get<ScanTask>(`/tasks/${id}`),
  analyzeTask: (id: number, findingIds?: number[]) =>
    axiosClient.post(`/tasks/${id}/analyze`, { finding_ids: findingIds || [] }),
  analyzeFindings: (findingIds: number[]) =>
    axiosClient.post('/findings/analyze', { finding_ids: findingIds }),

  // Findings
  listFindings: (params: {
    task_id?: number
    tool?: string
    severity?: string
    is_vulnerable?: boolean
    is_false_positive?: boolean
    min_risk_score?: number
    page?: number
    page_size?: number
  }) => axiosClient.get<FindingListResponse>('/findings', { params }),
  getFinding: (id: number) => axiosClient.get<Finding>(`/findings/${id}`),
  markFalsePositive: (id: number, isFP: boolean) =>
    axiosClient.patch(`/findings/${id}/false-positive`, null, { params: { is_false_positive: isFP } }),
  markFalsePositiveBatch: (findingIds: number[], isFalsePositive: boolean) =>
    axiosClient.patch('/findings/false-positive', { finding_ids: findingIds, is_false_positive: isFalsePositive }),
  analyzeFinding: (id: number) => axiosClient.post(`/findings/${id}/analyze`),

  // Stats
  getStats: (taskId?: number) =>
    axiosClient.get<Stats>('/stats', { params: taskId ? { task_id: taskId } : {} }),

  // System Settings
  getSettings: () => axiosClient.get<SystemSettings>('/settings'),
  updateSettings: (data: Partial<SystemSettings>) => axiosClient.put<SystemSettings>('/settings', data),
  resetSettings: () => axiosClient.post<SystemSettings>('/settings/reset'),

  // Analysis progress
  getTaskProgress: (taskId: number) => axiosClient.get<TaskProgress>(`/tasks/${taskId}/progress`),

  // Clear all
  deleteAllTasks: () => axiosClient.delete('/tasks'),
}

export default apiService
