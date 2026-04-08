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
  issue_group_count: number
}

export interface Finding {
  id: number
  task_id: number
  issue_group_id: number | null
  is_representative: boolean
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

export interface IssueGroup {
  id: number
  task_id: number
  representative_finding_id: number | null
  tool: string
  rule_id: string | null
  file_path: string | null
  line_start: number | null
  line_end: number | null
  message: string | null
  function_name: string | null
  member_count: number
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
  analyzed_at: string | null
  created_at: string
  updated_at: string
  member_ids: number[]
  member_findings: Finding[]
}

export interface IssueGroupListResponse {
  total: number
  items: IssueGroup[]
}

export interface Stats {
  scope: 'finding' | 'issue_group'
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

export type AnalysisTarget = 'finding' | 'issue_group'

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
  analyzeTask: (id: number, options?: { targetType?: AnalysisTarget; findingIds?: number[]; issueGroupIds?: number[] }) =>
    axiosClient.post(`/tasks/${id}/analyze`, {
      target_type: options?.targetType || 'finding',
      finding_ids: options?.findingIds || [],
      issue_group_ids: options?.issueGroupIds || [],
    }),
  analyzeFindings: (findingIds: number[]) =>
    axiosClient.post('/findings/analyze', { finding_ids: findingIds, target_type: 'finding' }),
  analyzeIssueGroups: (issueGroupIds: number[]) =>
    axiosClient.post('/issue-groups/analyze', { issue_group_ids: issueGroupIds, target_type: 'issue_group' }),

  // Findings
  listFindings: (params: {
    task_id?: number
    tool?: string
    severity?: string
    analyzed?: boolean
    is_vulnerable?: boolean
    is_false_positive?: boolean
    min_risk_score?: number
    page?: number
    page_size?: number
  }) => axiosClient.get<FindingListResponse>('/findings', { params }),
  listIssueGroups: (params: {
    task_id?: number
    tool?: string
    severity?: string
    analyzed?: boolean
    is_vulnerable?: boolean
    is_false_positive?: boolean
    min_risk_score?: number
    page?: number
    page_size?: number
  }) => axiosClient.get<IssueGroupListResponse>('/issue-groups', { params }),
  getFinding: (id: number) => axiosClient.get<Finding>(`/findings/${id}`),
  getIssueGroup: (id: number) => axiosClient.get<IssueGroup>(`/issue-groups/${id}`),
  markFalsePositive: (id: number, isFP: boolean) =>
    axiosClient.patch(`/findings/${id}/false-positive`, null, { params: { is_false_positive: isFP } }),
  markFalsePositiveBatch: (findingIds: number[], isFalsePositive: boolean) =>
    axiosClient.patch('/findings/false-positive', { finding_ids: findingIds, is_false_positive: isFalsePositive }),
  markIssueGroupFalsePositive: (id: number, isFalsePositive: boolean) =>
    axiosClient.patch(`/issue-groups/${id}/false-positive`, null, { params: { is_false_positive: isFalsePositive } }),
  markIssueGroupFalsePositiveBatch: (issueGroupIds: number[], isFalsePositive: boolean) =>
    axiosClient.patch('/issue-groups/false-positive', { issue_group_ids: issueGroupIds, is_false_positive: isFalsePositive }),
  analyzeFinding: (id: number) => axiosClient.post(`/findings/${id}/analyze`),
  analyzeIssueGroup: (id: number) => axiosClient.post(`/issue-groups/${id}/analyze`),

  // Stats
  getStats: (taskId?: number, scope: AnalysisTarget = 'finding') =>
    axiosClient.get<Stats>('/stats', { params: { ...(taskId ? { task_id: taskId } : {}), scope } }),

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
