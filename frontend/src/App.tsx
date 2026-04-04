import { Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import ReportList from './components/ReportList'
import ReportDetail from './components/ReportDetail'
import Upload from './components/Upload'

export default function App() {
  return (
    <div className="layout">
      <nav className="navbar">
        <span className="navbar-brand">🔍 MyLift</span>
        <NavLink to="/" end className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>总览</NavLink>
        <NavLink to="/reports" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>扫描报告</NavLink>
        <NavLink to="/upload" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>上传报告</NavLink>
      </nav>
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/reports" element={<ReportList />} />
          <Route path="/reports/:id" element={<ReportDetail />} />
          <Route path="/upload" element={<Upload />} />
        </Routes>
      </main>
    </div>
  )
}
