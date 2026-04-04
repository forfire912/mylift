import React from 'react'

interface RiskBarProps {
  score?: number | null
}

function getRiskColor(score: number): string {
  if (score >= 80) return '#ff4d4f'
  if (score >= 60) return '#fa8c16'
  if (score >= 40) return '#faad14'
  if (score >= 20) return '#52c41a'
  return '#8c8c8c'
}

export default function RiskBar({ score }: RiskBarProps) {
  if (score == null) return <span style={{ color: '#bbb', fontSize: 13 }}>未分析</span>
  const color = getRiskColor(score)
  return (
    <div className="risk-bar">
      <div className="risk-bar-bg">
        <div
          className="risk-bar-fill"
          style={{ width: `${Math.min(score, 100)}%`, background: color }}
        />
      </div>
      <span style={{ color, fontWeight: 600, fontSize: 13, minWidth: 32 }}>{score}</span>
    </div>
  )
}
