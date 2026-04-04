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

export const apiService = {
  // Tasks
  createTask: (data: { name: string; tool: string; raw_input: string }) =>
    axiosClient.post<ScanTask>('/tasks', data),
  listTasks: () => axiosClient.get<ScanTask[]>('/tasks'),
  getTask: (id: number) => axiosClient.get<ScanTask>(`/tasks/${id}`),
  analyzeTask: (id: number, findingIds?: number[]) =>
    axiosClient.post(`/tasks/${id}/analyze`, { finding_ids: findingIds || [] }),

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
  analyzeFinding: (id: number) => axiosClient.post(`/findings/${id}/analyze`),

  // Stats
  getStats: (taskId?: number) =>
    axiosClient.get<Stats>('/stats', { params: taskId ? { task_id: taskId } : {} }),
}

export default apiService
const BASE = '/api'

export interface Report {
  id: number
  name: string
  tool: string | null
  format: string
  created_at: string
  vulnerability_count: number
}

export interface ReportDetail extends Report {
  vulnerabilities: Vulnerability[]
}

export interface Vulnerability {
  id: number
  report_id: number
  rule_id: string | null
  severity: string | null
  message: string | null
  file_path: string | null
  start_line: number | null
  end_line: number | null
  start_column: number | null
  code_snippet: string | null
  cwe: string | null
  tags: string | null
}

export interface ReportStats {
  total_reports: number
  total_vulnerabilities: number
  by_severity: Record<string, number>
  by_tool: Record<string, number>
}

export interface UploadResult {
  report_id: number
  name: string
  tool: string | null
  format: string
  vulnerability_count: number
  message: string
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, options)
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(body.detail ?? `HTTP ${res.status}`)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

export const api = {
  stats: () => request<ReportStats>('/stats'),
  listReports: (skip = 0, limit = 50) =>
    request<Report[]>(`/reports?skip=${skip}&limit=${limit}`),
  getReport: (id: number) => request<ReportDetail>(`/reports/${id}`),
  deleteReport: (id: number) =>
    request<void>(`/reports/${id}`, { method: 'DELETE' }),
  listVulnerabilities: (reportId: number, severity?: string, ruleId?: string) => {
    const params = new URLSearchParams()
    if (severity) params.set('severity', severity)
    if (ruleId) params.set('rule_id', ruleId)
    return request<Vulnerability[]>(`/reports/${reportId}/vulnerabilities?${params}`)
  },
  upload: (file: File): Promise<UploadResult> => {
    const fd = new FormData()
    fd.append('file', file)
    return request<UploadResult>('/upload', { method: 'POST', body: fd })
  },
}
