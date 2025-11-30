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
        // Minimalist Swiss Style - Monochromatic Palette
        swiss: {
          white: '#FFFFFF',         // Pure white background
          offwhite: '#FAFAFA',      // Off-white surfaces
          light: '#F5F5F5',         // Light grey
          neutral: '#E0E0E0',       // Neutral grey
          medium: '#9E9E9E',        // Medium grey
          dark: '#424242',          // Dark grey
          black: '#000000',         // Pure black
          charcoal: '#212121',      // Charcoal black
        },
        // Neutral palette
        neutral: {
          50: '#FAFAFA',
          100: '#F5F5F5',
          200: '#EEEEEE',
          300: '#E0E0E0',
          400: '#BDBDBD',
          500: '#9E9E9E',
          600: '#757575',
          700: '#616161',
          800: '#424242',
          900: '#212121',
        },
        // Primary color accents (minimal use)
        accent: {
          red: '#E53935',           // Primary red accent
          blue: '#1E88E5',          // Primary blue accent
          yellow: '#FDD835',        // Primary yellow accent
          green: '#43A047',         // Primary green accent
        },
        // Severity colors - minimal and functional
        critical: {
          DEFAULT: '#E53935',       // Clean red
          light: '#FFEBEE',
          dark: '#C62828',
        },
        high: {
          DEFAULT: '#F57C00',       // Clean orange
          light: '#FFF3E0',
          dark: '#E65100',
        },
        medium: {
          DEFAULT: '#FDD835',       // Clean yellow
          light: '#FFFDE7',
          dark: '#F9A825',
        },
        low: {
          DEFAULT: '#43A047',       // Clean green
          light: '#E8F5E9',
          dark: '#2E7D32',
        },
        info: {
          DEFAULT: '#1E88E5',       // Clean blue
          light: '#E3F2FD',
          dark: '#1565C0',
        },
        // Legacy support (mapped to minimalist)
        command: {
          void: '#FFFFFF',
          deep: '#FAFAFA',
          surface: '#F5F5F5',
          panel: '#FFFFFF',
          border: '#E0E0E0',
          hover: '#F5F5F5',
          accent: '#EEEEEE',
        },
        retro: {
          void: '#FFFFFF',
          deep: '#FAFAFA',
          surface: '#F5F5F5',
          panel: '#FFFFFF',
          border: '#E0E0E0',
          hover: '#F5F5F5',
          grid: '#E0E0E0',
        },
        dark: {
          bg: '#FAFAFA',
          surface: '#FFFFFF',
          card: '#FFFFFF',
          border: '#E0E0E0',
          hover: '#F5F5F5',
        },
      },
      animation: {
        'fade-in': 'fade-in 0.2s ease-out',
        'slide-up': 'slide-up 0.3s ease-out',
        'slide-down': 'slide-down 0.3s ease-out',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'slide-up': {
          '0%': { transform: 'translateY(8px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'slide-down': {
          '0%': { transform: 'translateY(-8px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
      fontFamily: {
        'sans': ['Inter', 'Helvetica Neue', 'Arial', 'sans-serif'],
        'mono': ['SF Mono', 'Monaco', 'monospace'],
      },
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1.5', letterSpacing: '0.02em' }],
        'sm': ['0.875rem', { lineHeight: '1.5', letterSpacing: '0.01em' }],
        'base': ['1rem', { lineHeight: '1.6', letterSpacing: '0' }],
        'lg': ['1.125rem', { lineHeight: '1.6', letterSpacing: '-0.01em' }],
        'xl': ['1.25rem', { lineHeight: '1.5', letterSpacing: '-0.01em' }],
        '2xl': ['1.5rem', { lineHeight: '1.4', letterSpacing: '-0.02em' }],
        '3xl': ['1.875rem', { lineHeight: '1.3', letterSpacing: '-0.02em' }],
        '4xl': ['2.25rem', { lineHeight: '1.2', letterSpacing: '-0.03em' }],
      },
      boxShadow: {
        'sm': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'DEFAULT': '0 1px 3px 0 rgba(0, 0, 0, 0.1)',
        'md': '0 2px 4px 0 rgba(0, 0, 0, 0.06)',
        'lg': '0 4px 6px -1px rgba(0, 0, 0, 0.08)',
        'xl': '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
        'none': 'none',
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
    },
  },
  plugins: [],
}
