import React from 'react'

interface SeverityBadgeProps {
  severity?: string | null
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const sev = severity?.toLowerCase() || 'unknown'
  const label = SEVERITY_LABEL[sev] || severity || '未知'
  return <span className={`badge badge-${sev}`}>{label}</span>
}
