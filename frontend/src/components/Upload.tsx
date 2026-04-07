import { Link } from 'react-router-dom'

export default function Upload() {
  return (
    <div className="card" style={{ maxWidth: 720 }}>
      <div className="card-title">旧版上传页已停用</div>
      <p style={{ color: '#666', marginBottom: '1rem' }}>
        当前版本的上传入口已经迁移到扫描任务页的“上传扫描结果”弹窗。旧组件不再绑定历史 report 上传接口。
      </p>
      <div style={{ display: 'flex', gap: '.75rem' }}>
        <Link to="/"><button className="btn btn-primary">前往扫描任务</button></Link>
        <Link to="/settings"><button className="btn btn-outline">查看系统配置</button></Link>
      </div>
    </div>
  )
}
