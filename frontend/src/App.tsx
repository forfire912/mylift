import React from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import TaskListPage from './views/TaskListPage'
import FindingsPage from './views/FindingsPage'
import FindingDetailPage from './views/FindingDetailPage'
import StatsPage from './views/StatsPage'
import Dashboard from './components/Dashboard'
import ReportList from './components/ReportList'
import ReportDetail from './components/ReportDetail'
import Upload from './components/Upload'

export default function App() {
  return (
    <BrowserRouter>
      <div className="layout">
        <nav className="navbar">
          <span className="navbar-brand">🔍 MyLift</span>
          <NavLink to="/" end className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>总览</NavLink>
          <NavLink to="/tasks" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>扫描任务</NavLink>
          <NavLink to="/findings" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>漏洞列表</NavLink>
          <NavLink to="/reports" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>扫描报告</NavLink>
          <NavLink to="/upload" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>上传报告</NavLink>
          <NavLink to="/stats" className={({ isActive }) => 'navbar-link' + (isActive ? ' active' : '')}>统计分析</NavLink>
        </nav>
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/tasks" element={<TaskListPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:id" element={<FindingDetailPage />} />
            <Route path="/reports" element={<ReportList />} />
            <Route path="/reports/:id" element={<ReportDetail />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/stats" element={<StatsPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
