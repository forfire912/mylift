import React, { createContext, useContext, useState, useCallback } from 'react'

interface ProgressCtx {
  panelOpen: boolean
  activeTaskId: number | null
  openPanel: (taskId: number) => void
  closePanel: () => void
}

const ProgressContext = createContext<ProgressCtx>({
  panelOpen: false,
  activeTaskId: null,
  openPanel: () => {},
  closePanel: () => {},
})

export function ProgressProvider({ children }: { children: React.ReactNode }) {
  const [panelOpen, setPanelOpen] = useState(false)
  const [activeTaskId, setActiveTaskId] = useState<number | null>(null)

  const openPanel = useCallback((taskId: number) => {
    setActiveTaskId(taskId)
    setPanelOpen(true)
  }, [])

  const closePanel = useCallback(() => {
    setPanelOpen(false)
  }, [])

  return (
    <ProgressContext.Provider value={{ panelOpen, activeTaskId, openPanel, closePanel }}>
      {children}
    </ProgressContext.Provider>
  )
}

export function useProgress() {
  return useContext(ProgressContext)
}
