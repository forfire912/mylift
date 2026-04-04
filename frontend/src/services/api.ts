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

export interface Stats {
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
  stats: () => request<Stats>('/stats'),
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
