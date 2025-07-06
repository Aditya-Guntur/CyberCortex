"use client"

import { useEffect, useRef, useCallback, useState } from 'react'
import { useDashboard } from './use-dashboard'

// Web Speech API type declarations
declare global {
  interface Window {
    SpeechRecognition: typeof SpeechRecognition
    webkitSpeechRecognition: typeof SpeechRecognition
  }
  
  interface SpeechRecognition extends EventTarget {
    continuous: boolean
    grammars: SpeechGrammarList
    interimResults: boolean
    lang: string
    maxAlternatives: number
    onaudioend: ((this: SpeechRecognition, ev: Event) => any) | null
    onaudiostart: ((this: SpeechRecognition, ev: Event) => any) | null
    onend: ((this: SpeechRecognition, ev: Event) => any) | null
    onerror: ((this: SpeechRecognition, ev: SpeechRecognitionErrorEvent) => any) | null
    onnomatch: ((this: SpeechRecognition, ev: SpeechRecognitionEvent) => any) | null
    onresult: ((this: SpeechRecognition, ev: SpeechRecognitionEvent) => any) | null
    onsoundend: ((this: SpeechRecognition, ev: Event) => any) | null
    onsoundstart: ((this: SpeechRecognition, ev: Event) => any) | null
    onspeechend: ((this: SpeechRecognition, ev: Event) => any) | null
    onspeechstart: ((this: SpeechRecognition, ev: Event) => any) | null
    onstart: ((this: SpeechRecognition, ev: Event) => any) | null
    start(): void
    stop(): void
    abort(): void
  }
  
  interface SpeechRecognitionEvent extends Event {
    resultIndex: number
    results: SpeechRecognitionResultList
  }
  
  interface SpeechRecognitionErrorEvent extends Event {
    error: string
    message: string
  }
  
  interface SpeechRecognitionResultList {
    readonly length: number
    item(index: number): SpeechRecognitionResult
    [index: number]: SpeechRecognitionResult
  }
  
  interface SpeechRecognitionResult {
    readonly isFinal: boolean
    readonly length: number
    item(index: number): SpeechRecognitionAlternative
    [index: number]: SpeechRecognitionAlternative
  }
  
  interface SpeechRecognitionAlternative {
    readonly transcript: string
    readonly confidence: number
  }
  
  interface SpeechGrammarList {
    readonly length: number
    item(index: number): SpeechGrammar
    [index: number]: SpeechGrammar
    addFromURI(src: string, weight?: number): void
    addFromString(string: string, weight?: number): void
  }
  
  interface SpeechGrammar {
    readonly src: string
    readonly weight: number
  }
  
  var SpeechRecognition: {
    prototype: SpeechRecognition
    new(): SpeechRecognition
  }
  
  var webkitSpeechRecognition: {
    prototype: SpeechRecognition
    new(): SpeechRecognition
  }
}

interface UseVoiceOptions {
  language?: string
  continuous?: boolean
  interimResults?: boolean
  maxAlternatives?: number
  onResult?: (transcript: string, confidence: number) => void
  onError?: (error: any) => void
  onStart?: () => void
  onEnd?: () => void
}

export function useVoice(options: UseVoiceOptions = {}) {
  const {
    language = 'en-US',
    continuous = false,
    interimResults = true,
    maxAlternatives = 1,
    onResult,
    onError,
    onStart,
    onEnd
  } = options

  const recognition = useRef<SpeechRecognition | null>(null)
  const [isSupported, setIsSupported] = useState(false)
  const [isListening, setIsListening] = useState(false)
  const [transcript, setTranscript] = useState('')
  const [confidence, setConfidence] = useState(0)

  const { 
    voiceEnabled, 
    processVoiceCommand,
    enableVoice,
    disableVoice 
  } = useDashboard(state => ({
    voiceEnabled: state.voiceEnabled,
    processVoiceCommand: state.processVoiceCommand,
    enableVoice: state.enableVoice,
    disableVoice: state.disableVoice
  }))

  // Initialize speech recognition
  useEffect(() => {
    if (typeof window === 'undefined') return

    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition
    
    if (SpeechRecognition) {
      setIsSupported(true)
      recognition.current = new SpeechRecognition()
      
      const rec = recognition.current
      rec.lang = language
      rec.continuous = continuous
      rec.interimResults = interimResults
      rec.maxAlternatives = maxAlternatives

      rec.onstart = () => {
        setIsListening(true)
        useDashboard.setState({ listening: true })
        onStart?.()
      }

      rec.onend = () => {
        setIsListening(false)
        useDashboard.setState({ listening: false })
        onEnd?.()
      }

      rec.onresult = (event) => {
        let finalTranscript = ''
        let interimTranscript = ''
        let resultConfidence = 0

        for (let i = event.resultIndex; i < event.results.length; i++) {
          const result = event.results[i]
          const transcript = result[0].transcript
          const confidence = result[0].confidence

          if (result.isFinal) {
            finalTranscript += transcript
            resultConfidence = confidence
          } else {
            interimTranscript += transcript
          }
        }

        const fullTranscript = finalTranscript || interimTranscript
        setTranscript(fullTranscript)
        setConfidence(resultConfidence)

        if (finalTranscript) {
          onResult?.(finalTranscript, resultConfidence)
          
          // Process voice command if enabled
          if (voiceEnabled) {
            processVoiceCommand(finalTranscript)
          }
        }
      }

      rec.onerror = (event) => {
        console.error('Speech recognition error:', event.error)
        setIsListening(false)
        useDashboard.setState({ listening: false })
        onError?.(event)
      }
    } else {
      setIsSupported(false)
      console.warn('Speech recognition not supported in this browser')
    }

    return () => {
      if (recognition.current) {
        recognition.current.abort()
      }
    }
  }, [language, continuous, interimResults, maxAlternatives, onResult, onError, onStart, onEnd, voiceEnabled, processVoiceCommand])

  const startListening = useCallback(() => {
    if (recognition.current && !isListening && isSupported) {
      try {
        recognition.current.start()
      } catch (error) {
        console.error('Failed to start speech recognition:', error)
      }
    }
  }, [isListening, isSupported])

  const stopListening = useCallback(() => {
    if (recognition.current && isListening) {
      recognition.current.stop()
    }
  }, [isListening])

  const toggleListening = useCallback(() => {
    if (isListening) {
      stopListening()
    } else {
      startListening()
    }
  }, [isListening, startListening, stopListening])

  // Voice commands mapping
  const executeVoiceCommand = useCallback(async (command: string) => {
    const normalizedCommand = command.toLowerCase().trim()
    
    // Security scan commands
    if (normalizedCommand.includes('scan') || normalizedCommand.includes('assess')) {
      if (normalizedCommand.includes('network')) {
        // Extract target if mentioned
        const targetMatch = normalizedCommand.match(/scan\s+(\S+)|assess\s+(\S+)/)
        const target = targetMatch?.[1] || targetMatch?.[2] || '192.168.1.0/24'
        
        await processVoiceCommand(`scan network ${target}`)
      } else if (normalizedCommand.includes('vulnerability') || normalizedCommand.includes('vuln')) {
        await processVoiceCommand('scan vulnerability')
      } else {
        await processVoiceCommand('scan network')
      }
    }
    
    // Status commands
    else if (normalizedCommand.includes('status') || normalizedCommand.includes('dashboard')) {
      await processVoiceCommand('show status')
    }
    
    // Alert commands
    else if (normalizedCommand.includes('alert') || normalizedCommand.includes('notification')) {
      await processVoiceCommand('show alerts')
    }
    
    // Report commands
    else if (normalizedCommand.includes('report') || normalizedCommand.includes('summary')) {
      await processVoiceCommand('generate report')
    }
    
    // Navigation commands
    else if (normalizedCommand.includes('go to') || normalizedCommand.includes('navigate')) {
      if (normalizedCommand.includes('vulnerability')) {
        await processVoiceCommand('navigate vulnerabilities')
      } else if (normalizedCommand.includes('compliance')) {
        await processVoiceCommand('navigate compliance')
      } else if (normalizedCommand.includes('assessment')) {
        await processVoiceCommand('navigate assessments')
      }
    }
    
    // Help command
    else if (normalizedCommand.includes('help') || normalizedCommand.includes('command')) {
      await processVoiceCommand('show help')
    }
    
    else {
      console.log('Unknown voice command:', command)
    }
  }, [processVoiceCommand])

  return {
    isSupported,
    isListening,
    transcript,
    confidence,
    voiceEnabled,
    startListening,
    stopListening,
    toggleListening,
    enableVoice,
    disableVoice,
    executeVoiceCommand
  }
}

// Voice command patterns for reference
export const VOICE_COMMANDS = {
  scan: [
    'scan network',
    'scan [target]',
    'assess network',
    'run vulnerability scan',
    'start assessment'
  ],
  status: [
    'show status',
    'dashboard',
    'security status',
    'system status'
  ],
  alerts: [
    'show alerts',
    'notifications',
    'security alerts'
  ],
  reports: [
    'generate report',
    'show report',
    'compliance report',
    'security summary'
  ],
  navigation: [
    'go to vulnerabilities',
    'navigate to compliance',
    'show assessments',
    'open dashboard'
  ],
  help: [
    'help',
    'voice commands',
    'what can I say'
  ]
}

