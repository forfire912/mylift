import React from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import TaskListPage from './views/TaskListPage'
import FindingsPage from './views/FindingsPage'
import FindingDetailPage from './views/FindingDetailPage'
import StatsPage from './views/StatsPage'
import SettingsPage from './views/SettingsPage'
import { ProgressProvider } from './context/ProgressContext'
import AgentProgressPanel from './components/AgentProgressPanel'

export default function App() {
  return (
    <BrowserRouter>
      <ProgressProvider>
        <div className="layout" style={{ marginRight: '420px' }}>
          <nav className="navbar">
            <span className="navbar-brand">🔍 MyLift</span>
            <NavLink to="/" end className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>扫描任务</NavLink>
            <NavLink to="/findings" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>漏洞列表</NavLink>
            <NavLink to="/stats" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>统计分析</NavLink>
            <NavLink to="/settings" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>系统配置</NavLink>
          </nav>
          <main className="main-content">
            <Routes>
              <Route path="/" element={<TaskListPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/findings/:id" element={<FindingDetailPage />} />
              <Route path="/stats" element={<StatsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </main>
          <AgentProgressPanel />
        </div>
      </ProgressProvider>
    </BrowserRouter>
  )
}
