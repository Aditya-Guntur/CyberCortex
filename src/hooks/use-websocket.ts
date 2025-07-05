"use client"

import { useEffect, useRef, useCallback } from 'react'
import { useDashboard } from './use-dashboard'

interface UseWebSocketOptions {
  url?: string
  reconnectInterval?: number
  maxReconnectAttempts?: number
  onConnect?: () => void
  onDisconnect?: () => void
  onError?: (error: Event) => void
  onMessage?: (data: any) => void
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    url = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws',
    reconnectInterval = 5000,
    maxReconnectAttempts = 10,
    onConnect,
    onDisconnect,
    onError,
    onMessage
  } = options

  const ws = useRef<WebSocket | null>(null)
  const reconnectAttempts = useRef(0)
  const reconnectTimer = useRef<NodeJS.Timeout | null>(null)
  
  const { connected, handleMessage } = useDashboard(state => ({
    connected: state.connected,
    handleMessage: state.handleMessage
  }))

  const connect = useCallback(() => {
    if (typeof window === 'undefined') return
    
    try {
      ws.current = new WebSocket(url)
      
      ws.current.onopen = () => {
        console.log('WebSocket connected')
        reconnectAttempts.current = 0
        useDashboard.setState({ connected: true })
        onConnect?.()
      }
      
      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          handleMessage(data)
          onMessage?.(data)
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error)
        }
      }
      
      ws.current.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason)
        useDashboard.setState({ connected: false })
        onDisconnect?.()
        
        // Attempt to reconnect if not a clean close
        if (event.code !== 1000 && reconnectAttempts.current < maxReconnectAttempts) {
          reconnectAttempts.current++
          console.log(`Attempting to reconnect (${reconnectAttempts.current}/${maxReconnectAttempts})...`)
          
          reconnectTimer.current = setTimeout(() => {
            connect()
          }, reconnectInterval)
        }
      }
      
      ws.current.onerror = (error) => {
        console.error('WebSocket error:', error)
        onError?.(error)
      }
      
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error)
    }
  }, [url, reconnectInterval, maxReconnectAttempts, onConnect, onDisconnect, onError, onMessage, handleMessage])

  const disconnect = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current)
      reconnectTimer.current = null
    }
    
    if (ws.current) {
      ws.current.close(1000, 'Manual disconnect')
      ws.current = null
    }
    
    useDashboard.setState({ connected: false })
  }, [])

  const sendMessage = useCallback((data: any) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data))
      return true
    }
    return false
  }, [])

  useEffect(() => {
    connect()
    
    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  return {
    connected,
    connect,
    disconnect,
    sendMessage
  }
}