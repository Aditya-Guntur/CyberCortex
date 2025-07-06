import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import { useEffect, useRef } from 'react';

interface WebSocketState {
  connected: boolean;
  connecting: boolean;
  socket: WebSocket | null;
  messageHandlers: Record<string, ((data: any) => void)[]>;
  
  // Actions
  connect: () => void;
  disconnect: () => void;
  sendMessage: (type: string, data: any) => boolean;
  addMessageHandler: (type: string, handler: (data: any) => void) => () => void;
  removeMessageHandler: (type: string, handler: (data: any) => void) => void;
}

export const useWebSocket = create<WebSocketState>()(
  subscribeWithSelector((set, get) => ({
    connected: false,
    connecting: false,
    socket: null,
    messageHandlers: {},
    
    connect: () => {
      const { socket, connecting } = get();
      
      // Don't connect if already connected or connecting
      if (socket || connecting) return;
      
      set({ connecting: true });
      
      try {
        // Get WebSocket URL from environment or use default
        const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws';
        const newSocket = new WebSocket(wsUrl);
        
        newSocket.onopen = () => {
          console.log('WebSocket connected');
          set({ connected: true, connecting: false, socket: newSocket });
        };
        
        newSocket.onclose = () => {
          console.log('WebSocket disconnected');
          set({ connected: false, connecting: false, socket: null });
          
          // Attempt to reconnect after 5 seconds
          setTimeout(() => {
            const { connected, connecting } = get();
            if (!connected && !connecting) {
              get().connect();
            }
          }, 5000);
        };
        
        newSocket.onerror = (error) => {
          console.error('WebSocket error:', error);
          set({ connected: false, connecting: false, socket: null });
        };
        
        newSocket.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            const { type, data } = message;
            
            // Call all registered handlers for this message type
            const handlers = get().messageHandlers[type] || [];
            handlers.forEach(handler => {
              try {
                handler(data);
              } catch (handlerError) {
                console.error(`Error in message handler for ${type}:`, handlerError);
              }
            });
          } catch (error) {
            console.error('Error parsing WebSocket message:', error);
          }
        };
      } catch (error) {
        console.error('Error connecting to WebSocket:', error);
        set({ connecting: false });
      }
    },
    
    disconnect: () => {
      const { socket } = get();
      
      if (socket) {
        socket.close();
        set({ connected: false, socket: null });
      }
    },
    
    sendMessage: (type, data) => {
      const { socket, connected } = get();
      
      if (!socket || !connected) {
        console.warn('Cannot send message: WebSocket not connected');
        return false;
      }
      
      try {
        socket.send(JSON.stringify({ type, data }));
        return true;
      } catch (error) {
        console.error('Error sending WebSocket message:', error);
        return false;
      }
    },
    
    addMessageHandler: (type, handler) => {
      set(state => {
        const handlers = state.messageHandlers[type] || [];
        
        return {
          messageHandlers: {
            ...state.messageHandlers,
            [type]: [...handlers, handler]
          }
        };
      });
      
      // Return a function to remove this handler
      return () => get().removeMessageHandler(type, handler);
    },
    
    removeMessageHandler: (type, handler) => {
      set(state => {
        const handlers = state.messageHandlers[type] || [];
        
        return {
          messageHandlers: {
            ...state.messageHandlers,
            [type]: handlers.filter(h => h !== handler)
          }
        };
      });
    }
  }))
);

// React hook for using WebSocket in components
export function useWebSocketConnection() {
  const { connected, connect, disconnect, sendMessage } = useWebSocket();
  
  // Connect on component mount
  useEffect(() => {
    connect();
    
    // Disconnect on component unmount
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);
  
  // Ping to keep connection alive
  useEffect(() => {
    if (!connected) return;
    
    const intervalId = setInterval(() => {
      sendMessage('ping', { timestamp: new Date().toISOString() });
    }, 30000); // Every 30 seconds
    
    return () => {
      clearInterval(intervalId);
    };
  }, [connected, sendMessage]);
  
  return { connected, sendMessage };
}

// React hook for subscribing to specific message types
export function useWebSocketMessage<T = any>(
  type: string, 
  callback: (data: T) => void
) {
  const callbackRef = useRef(callback);
  const { addMessageHandler } = useWebSocket();
  
  // Update callback ref when callback changes
  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);
  
  // Subscribe to message type
  useEffect(() => {
    const handler = (data: T) => {
      callbackRef.current(data);
    };
    
    const unsubscribe = addMessageHandler(type, handler);
    
    return () => {
      unsubscribe();
    };
  }, [type, addMessageHandler]);
}