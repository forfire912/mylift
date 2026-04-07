import { Link } from 'react-router-dom'

export default function ReportList() {
  return (
    <div className="card">
      <div className="card-title">旧版报告列表已停用</div>
      <p style={{ color: '#666', marginBottom: '1rem' }}>
        当前导航已改为扫描任务、漏洞列表和统计分析。这个旧组件不再连接后端接口，仅保留为兼容页面，避免阻塞前端构建。
      </p>
      <div style={{ display: 'flex', gap: '.75rem' }}>
        <Link to="/"><button className="btn btn-primary">查看扫描任务</button></Link>
        <Link to="/stats"><button className="btn btn-outline">查看统计分析</button></Link>
      </div>
    </div>
  )
}
