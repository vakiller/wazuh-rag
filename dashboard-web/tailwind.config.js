/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Command Center dark theme - Unique color palette
        command: {
          void: '#000509',          // Deep space background
          deep: '#0a0e1a',          // Primary background
          surface: '#111827',       // Surface elements
          panel: '#1a1f2e',         // Panel backgrounds
          border: '#232937',        // Borders
          hover: '#2a3142',         // Hover states
          accent: '#141b2d',        // Accent dark
        },
        // Neon accent colors with glow
        neon: {
          cyan: '#00f0ff',          // Primary neon
          magenta: '#ff00e5',       // Secondary neon
          lime: '#b4ff39',          // Success neon
          amber: '#ffb800',         // Warning neon
        },
        // Severity colors with neon variants
        critical: {
          DEFAULT: '#ff0844',       // Neon red
          glow: 'rgba(255, 8, 68, 0.5)',
          bg: 'rgba(255, 8, 68, 0.1)',
        },
        high: {
          DEFAULT: '#ff6b35',       // Neon orange
          glow: 'rgba(255, 107, 53, 0.5)',
          bg: 'rgba(255, 107, 53, 0.1)',
        },
        medium: {
          DEFAULT: '#ffb800',       // Neon amber
          glow: 'rgba(255, 184, 0, 0.5)',
          bg: 'rgba(255, 184, 0, 0.1)',
        },
        low: {
          DEFAULT: '#b4ff39',       // Neon lime
          glow: 'rgba(180, 255, 57, 0.5)',
          bg: 'rgba(180, 255, 57, 0.1)',
        },
        info: {
          DEFAULT: '#00f0ff',       // Neon cyan
          glow: 'rgba(0, 240, 255, 0.5)',
          bg: 'rgba(0, 240, 255, 0.1)',
        },
        // Legacy dark theme colors (for backwards compatibility)
        dark: {
          bg: '#0a0e1a',
          surface: '#0f1419',
          card: '#1a1f2e',
          border: '#2a3142',
          hover: '#252b3d',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite',
        'scan-line': 'scan-line 4s linear infinite',
        'slide-in-right': 'slide-in-right 0.3s ease-out',
        'slide-in-left': 'slide-in-left 0.3s ease-out',
        'fade-in-up': 'fade-in-up 0.4s ease-out',
        'hexagon-pulse': 'hexagon-pulse 3s ease-in-out infinite',
      },
      keyframes: {
        'glow-pulse': {
          '0%, 100%': {
            boxShadow: '0 0 5px currentColor, 0 0 10px currentColor',
            opacity: '1'
          },
          '50%': {
            boxShadow: '0 0 20px currentColor, 0 0 30px currentColor',
            opacity: '0.8'
          },
        },
        'scan-line': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'slide-in-right': {
          '0%': { transform: 'translateX(20px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        'slide-in-left': {
          '0%': { transform: 'translateX(-20px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        'fade-in-up': {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'hexagon-pulse': {
          '0%, 100%': { transform: 'scale(1)', opacity: '0.3' },
          '50%': { transform: 'scale(1.05)', opacity: '0.5' },
        },
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        'sans': ['Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'hex-pattern': "url(\"data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M30 0l25.98 15v30L30 60 4.02 45V15z' fill='none' stroke='%23232937' stroke-width='1'/%3E%3C/svg%3E\")",
        'grid-pattern': "url(\"data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M 100 0 L 0 0 0 100' fill='none' stroke='%23232937' stroke-width='1'/%3E%3C/svg%3E\")",
      },
      clipPath: {
        'hexagon': 'polygon(30% 0%, 70% 0%, 100% 50%, 70% 100%, 30% 100%, 0% 50%)',
        'diagonal': 'polygon(0 0, 100% 0, 100% 85%, 0 100%)',
      },
    },
  },
  plugins: [],
}
