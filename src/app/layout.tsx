import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'
import { ThemeProvider } from '@/components/theme-provider'
import { Toaster } from '@/components/ui/toaster'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })
const jetbrainsMono = JetBrains_Mono({ 
  subsets: ['latin'], 
  variable: '--font-jetbrains-mono' 
})

export const metadata: Metadata = {
  title: 'CyberCortex - Autonomous Security Validation Platform',
  description: 'Multi-agent cybersecurity platform with AI-powered threat detection and automated security validation',
  keywords: ['cybersecurity', 'AI', 'security validation', 'threat detection', 'multi-agent'],
  authors: [{ name: 'CyberCortex Team' }],
  openGraph: {
    title: 'CyberCortex - Autonomous Security Validation Platform',
    description: 'Multi-agent cybersecurity platform with AI-powered threat detection',
    type: 'website',
    locale: 'en_US',
  },
  robots: {
    index: true,
    follow: true,
  },
  viewport: {
    width: 'device-width',
    initialScale: 1,
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased bg-background text-foreground`}>
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          {children}
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  )
}