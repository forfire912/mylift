import React, { createContext, useContext, useState, useCallback } from 'react'

interface ProgressCtx {
  panelOpen: boolean
  activeTaskId: number | null
  refreshToken: number
  openPanel: (taskId: number) => void
  closePanel: () => void
}

const ProgressContext = createContext<ProgressCtx>({
  panelOpen: false,
  activeTaskId: null,
  refreshToken: 0,
  openPanel: () => {},
  closePanel: () => {},
})

export function ProgressProvider({ children }: { children: React.ReactNode }) {
  const [panelOpen, setPanelOpen] = useState(false)
  const [activeTaskId, setActiveTaskId] = useState<number | null>(null)
  const [refreshToken, setRefreshToken] = useState(0)

  const openPanel = useCallback((taskId: number) => {
    setActiveTaskId(taskId)
    setPanelOpen(true)
    setRefreshToken(prev => prev + 1)
  }, [])

  const closePanel = useCallback(() => {
    setPanelOpen(false)
  }, [])

  return (
    <ProgressContext.Provider value={{ panelOpen, activeTaskId, refreshToken, openPanel, closePanel }}>
      {children}
    </ProgressContext.Provider>
  )
}

export function useProgress() {
  return useContext(ProgressContext)
}
