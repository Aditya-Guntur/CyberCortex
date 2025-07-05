// Add any global test setup here
import '@testing-library/jest-dom'

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
})

// Mock IntersectionObserver
class MockIntersectionObserver {
  constructor(callback) {
    this.callback = callback
  }
  observe() { return null }
  unobserve() { return null }
  disconnect() { return null }
}

window.IntersectionObserver = MockIntersectionObserver

// Mock fetch
global.fetch = jest.fn(() =>
  Promise.resolve({
    json: () => Promise.resolve({}),
    ok: true,
    status: 200,
    text: () => Promise.resolve(''),
  })
)

// Mock WebSocket
global.WebSocket = class MockWebSocket {
  constructor(url) {
    this.url = url
    this.readyState = 1
    setTimeout(() => {
      if (this.onopen) this.onopen()
    })
  }
  send() {}
  close() {}
}

// Suppress console errors during tests
const originalConsoleError = console.error
console.error = (...args) => {
  if (
    typeof args[0] === 'string' &&
    (args[0].includes('React does not recognize the') ||
      args[0].includes('Warning:'))
  ) {
    return
  }
  originalConsoleError(...args)
}