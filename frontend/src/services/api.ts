import axios from 'axios'

const api = axios.create({
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

export const apiService = {
  // Tasks
  createTask: (data: { name: string; tool: string; raw_input: string }) =>
    api.post<ScanTask>('/tasks', data),
  listTasks: () => api.get<ScanTask[]>('/tasks'),
  getTask: (id: number) => api.get<ScanTask>(`/tasks/${id}`),
  analyzeTask: (id: number, findingIds?: number[]) =>
    api.post(`/tasks/${id}/analyze`, { finding_ids: findingIds || [] }),

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
  }) => api.get<FindingListResponse>('/findings', { params }),
  getFinding: (id: number) => api.get<Finding>(`/findings/${id}`),
  markFalsePositive: (id: number, isFP: boolean) =>
    api.patch(`/findings/${id}/false-positive`, null, { params: { is_false_positive: isFP } }),
  analyzeFinding: (id: number) => api.post(`/findings/${id}/analyze`),

  // Stats
  getStats: (taskId?: number) =>
    api.get<Stats>('/stats', { params: taskId ? { task_id: taskId } : {} }),
}

export default apiService
