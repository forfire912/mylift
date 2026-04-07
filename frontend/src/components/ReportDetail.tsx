import { Link } from 'react-router-dom'

export default function ReportDetail() {
  return (
    <div className="card">
      <div className="card-title">旧版报告详情页已停用</div>
      <p style={{ color: '#666', marginBottom: '1rem' }}>
        当前产品已经切换为任务与漏洞视图，旧版 report 详情组件仅保留为兼容占位，不再绑定历史 API。
      </p>
      <div style={{ display: 'flex', gap: '.75rem' }}>
        <Link to="/"><button className="btn btn-primary">前往扫描任务</button></Link>
        <Link to="/findings"><button className="btn btn-outline">前往漏洞列表</button></Link>
      </div>
    </div>
  )
}
