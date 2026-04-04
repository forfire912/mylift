import React from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import TaskListPage from './views/TaskListPage'
import FindingsPage from './views/FindingsPage'
import FindingDetailPage from './views/FindingDetailPage'
import StatsPage from './views/StatsPage'

export default function App() {
  return (
    <BrowserRouter>
      <nav>
        <span className="logo">🔍 MyLift</span>
        <NavLink to="/tasks" className={({ isActive }) => isActive ? 'active' : ''}>扫描任务</NavLink>
        <NavLink to="/findings" className={({ isActive }) => isActive ? 'active' : ''}>漏洞列表</NavLink>
        <NavLink to="/stats" className={({ isActive }) => isActive ? 'active' : ''}>统计分析</NavLink>
      </nav>
      <div style={{ padding: '24px' }}>
        <Routes>
          <Route path="/" element={<Navigate to="/tasks" replace />} />
          <Route path="/tasks" element={<TaskListPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/findings/:id" element={<FindingDetailPage />} />
          <Route path="/stats" element={<StatsPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
