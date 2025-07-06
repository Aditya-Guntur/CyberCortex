"use client"

import { create } from 'zustand'
import { subscribeWithSelector } from 'zustand/middleware'
import { DashboardState, DashboardActions, WebSocketMessage, VoiceCommand } from '@/types/dashboard'

interface DashboardStore extends DashboardState, DashboardActions {}

export const useDashboard = create<DashboardStore>()(
  subscribeWithSelector((set, get) => ({
    // Initial state
    securityMetrics: null,
    threats: [],
    vulnerabilities: [],
    assessments: [],
    compliance: [],
    agents: [],
    alerts: [],
    loading: false,
    error: null,
    filters: {
      timeRange: {
        start: new Date(Date.now() - 24 * 60 * 60 * 1000), // 24 hours ago
        end: new Date(),
        preset: '24h'
      },
      severity: ['critical', 'high', 'medium', 'low', 'info'],
      categories: [],
      agents: [],
      status: []
    },
    selectedTimeRange: '24h',
    darkMode: true,
    sidebarCollapsed: false,
    connected: false,
    lastUpdate: null,
    voiceEnabled: false,
    listening: false,
    lastCommand: null,

    // Data actions
    fetchSecurityMetrics: async () => {
      set({ loading: true, error: null })
      try {
        const response = await fetch('/api/dashboard/metrics')
        const data = await response.json()
        
        if (data.success) {
          set({ 
            securityMetrics: data.data,
            lastUpdate: new Date(),
            loading: false 
          })
        } else {
          set({ error: data.error || 'Failed to fetch metrics', loading: false })
        }
      } catch (error) {
        set({ error: 'Network error', loading: false })
      }
    },

    fetchThreats: async (filters) => {
      try {
        const currentFilters = filters || get().filters
        const params = new URLSearchParams({
          timeRange: currentFilters.timeRange?.preset || '24h',
          severity: currentFilters.severity?.join(',') || 'critical,high,medium,low,info',
        })

        const response = await fetch(`/api/threats?${params}`)
        const data = await response.json()
        
        if (data.success) {
          set({ threats: data.data })
        }
      } catch (error) {
        console.error('Failed to fetch threats:', error)
      }
    },

    fetchVulnerabilities: async (filters) => {
      try {
        const currentFilters = filters || get().filters
        const params = new URLSearchParams({
          status: currentFilters.status?.join(',') || '',
          severity: currentFilters.severity?.join(',') || 'critical,high,medium,low,info',
        })

        const response = await fetch(`/api/vulnerabilities?${params}`)
        const data = await response.json()
        
        if (data.success) {
          set({ vulnerabilities: data.data })
        }
      } catch (error) {
        console.error('Failed to fetch vulnerabilities:', error)
      }
    },

    fetchAssessments: async (filters) => {
      try {
        const response = await fetch('/api/assessments')
        const data = await response.json()
        
        if (data.success) {
          set({ assessments: data.data })
        }
      } catch (error) {
        console.error('Failed to fetch assessments:', error)
      }
    },

    fetchCompliance: async () => {
      try {
        const response = await fetch('/api/compliance')
        const data = await response.json()
        
        if (data.success) {
          set({ compliance: data.data })
        }
      } catch (error) {
        console.error('Failed to fetch compliance:', error)
      }
    },

    fetchAgents: async () => {
      try {
        const response = await fetch('/api/agents')
        const data = await response.json()
        
        if (data.success) {
          set({ agents: data.data })
        }
      } catch (error) {
        console.error('Failed to fetch agents:', error)
      }
    },

    fetchAlerts: async (filters) => {
      try {
        const currentFilters = filters || get().filters
        const params = new URLSearchParams({
          severity: currentFilters.severity?.join(',') || 'critical,high,medium,low,info',
          status: 'new,acknowledged,investigating',
        })

        const response = await fetch(`/api/alerts?${params}`)
        const data = await response.json()
        
        if (data.success) {
          set({ alerts: data.data })
        }
      } catch (error) {
        console.error('Failed to fetch alerts:', error)
      }
    },

    // Assessment actions
    startAssessment: async (type, target, options = {}) => {
      try {
        const response = await fetch('/api/assessments', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type, target, options })
        })
        
        const data = await response.json()
        
        if (data.success) {
          // Refresh assessments
          get().fetchAssessments()
          return data.data.id
        } else {
          throw new Error(data.error)
        }
      } catch (error) {
        set({ error: `Failed to start assessment: ${error}` })
        throw error
      }
    },

    stopAssessment: async (id) => {
      try {
        const response = await fetch(`/api/assessments/${id}/stop`, {
          method: 'POST'
        })
        
        if (response.ok) {
          get().fetchAssessments()
        }
      } catch (error) {
        console.error('Failed to stop assessment:', error)
      }
    },

    scheduleAssessment: async (schedule) => {
      try {
        const response = await fetch('/api/assessments/schedule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(schedule)
        })
        
        if (!response.ok) {
          throw new Error('Failed to schedule assessment')
        }
      } catch (error) {
        set({ error: `Failed to schedule assessment: ${error}` })
      }
    },

    // Vulnerability actions
    updateVulnerabilityStatus: async (id, status) => {
      try {
        const response = await fetch(`/api/vulnerabilities/${id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status })
        })
        
        if (response.ok) {
          get().fetchVulnerabilities()
        }
      } catch (error) {
        console.error('Failed to update vulnerability:', error)
      }
    },

    assignVulnerability: async (id, assignee) => {
      try {
        const response = await fetch(`/api/vulnerabilities/${id}/assign`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ assignee })
        })
        
        if (response.ok) {
          get().fetchVulnerabilities()
        }
      } catch (error) {
        console.error('Failed to assign vulnerability:', error)
      }
    },

    // Alert actions
    acknowledgeAlert: async (id) => {
      try {
        const response = await fetch(`/api/alerts/${id}/acknowledge`, {
          method: 'POST'
        })
        
        if (response.ok) {
          get().fetchAlerts()
        }
      } catch (error) {
        console.error('Failed to acknowledge alert:', error)
      }
    },

    resolveAlert: async (id) => {
      try {
        const response = await fetch(`/api/alerts/${id}/resolve`, {
          method: 'POST'
        })
        
        if (response.ok) {
          get().fetchAlerts()
        }
      } catch (error) {
        console.error('Failed to resolve alert:', error)
      }
    },

    // UI actions
    setFilters: (filters) => {
      set(state => ({
        filters: { ...state.filters, ...filters }
      }))
    },

    setTimeRange: (range) => {
      const now = new Date()
      let start: Date
      
      switch (range) {
        case '1h':
          start = new Date(now.getTime() - 60 * 60 * 1000)
          break
        case '24h':
          start = new Date(now.getTime() - 24 * 60 * 60 * 1000)
          break
        case '7d':
          start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
          break
        case '30d':
          start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
          break
        case '90d':
          start = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000)
          break
        default:
          start = new Date(now.getTime() - 24 * 60 * 60 * 1000)
      }
      
      set(state => ({
        selectedTimeRange: range,
        filters: {
          ...state.filters,
          timeRange: { start, end: now, preset: range as any }
        }
      }))
    },

    toggleDarkMode: () => {
      set(state => ({ darkMode: !state.darkMode }))
    },

    toggleSidebar: () => {
      set(state => ({ sidebarCollapsed: !state.sidebarCollapsed }))
    },

    // Voice actions
    enableVoice: () => {
      set({ voiceEnabled: true })
    },

    disableVoice: () => {
      set({ voiceEnabled: false, listening: false })
    },

    processVoiceCommand: async (command) => {
      try {
        const response = await fetch('/api/voice/process', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command })
        })
        
        const data = await response.json()
        
        if (data.success) {
          const voiceCommand: VoiceCommand = {
            command,
            confidence: data.confidence || 0.8,
            intent: data.intent,
            parameters: data.parameters || {},
            timestamp: new Date()
          }
          
          set({ lastCommand: voiceCommand })
          
          // Execute the command
          switch (data.intent) {
            case 'scan':
              if (data.parameters.target) {
                await get().startAssessment(
                  data.parameters.type || 'network-discovery',
                  data.parameters.target
                )
              }
              break
            case 'status':
              await get().fetchSecurityMetrics()
              break
            case 'report':
              // Navigate to reports
              break
          }
        }
      } catch (error) {
        console.error('Failed to process voice command:', error)
      }
    },

    // WebSocket actions
    connect: () => {
      if (typeof window === 'undefined') return
      
      const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws'
      const ws = new WebSocket(wsUrl)
      
      ws.onopen = () => {
        set({ connected: true })
        console.log('WebSocket connected')
      }
      
      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)
          get().handleMessage(message)
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error)
        }
      }
      
      ws.onclose = () => {
        set({ connected: false })
        console.log('WebSocket disconnected')
        
        // Attempt to reconnect after 5 seconds
        setTimeout(() => {
          if (!get().connected) {
            get().connect()
          }
        }, 5000)
      }
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
        set({ connected: false })
      }
    },

    disconnect: () => {
      set({ connected: false })
    },

    handleMessage: (message) => {
      const { type, payload } = message
      
      switch (type) {
        case 'security_event':
          // Update relevant data based on event
          if (payload.type === 'threat_detected') {
            get().fetchThreats()
          } else if (payload.type === 'vulnerability_found') {
            get().fetchVulnerabilities()
          }
          break
          
        case 'assessment_update':
          // Update specific assessment
          set(state => ({
            assessments: state.assessments.map(assessment =>
              assessment.id === payload.id
                ? { ...assessment, ...payload }
                : assessment
            )
          }))
          break
          
        case 'agent_status':
          // Update agent status
          set(state => ({
            agents: state.agents.map(agent =>
              agent.id === payload.id
                ? { ...agent, ...payload }
                : agent
            )
          }))
          break
          
        case 'alert':
          // Add new alert
          set(state => ({
            alerts: [payload, ...state.alerts]
          }))
          break
          
        case 'metrics_update':
          // Update security metrics
          set({ securityMetrics: payload, lastUpdate: new Date() })
          break
      }
    }
  }))
)

// Selectors for optimized re-renders
export const useSecurityMetrics = () => useDashboard(state => state.securityMetrics)
export const useThreats = () => useDashboard(state => state.threats)
export const useVulnerabilities = () => useDashboard(state => state.vulnerabilities)
export const useAssessments = () => useDashboard(state => state.assessments)
export const useCompliance = () => useDashboard(state => state.compliance)
export const useAgents = () => useDashboard(state => state.agents)
export const useAlerts = () => useDashboard(state => state.alerts)
export const useDashboardLoading = () => useDashboard(state => state.loading)
export const useDashboardError = () => useDashboard(state => state.error)
export const useFilters = () => useDashboard(state => state.filters)
export const useVoiceState = () => useDashboard(state => ({ 
  enabled: state.voiceEnabled, 
  listening: state.listening,
  lastCommand: state.lastCommand 
}))
export const useConnectionState = () => useDashboard(state => state.connected)