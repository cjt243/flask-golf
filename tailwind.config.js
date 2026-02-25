/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    './app.py',
  ],
  safelist: [
    // Dynamic classes in admin_tiers.html: bg-{{ color }}-600/20 text-{{ color }}-400
    'bg-green-600/20', 'text-green-400',
    'bg-blue-600/20', 'text-blue-400',
    'bg-gray-600/20', 'text-gray-400',
    // Dynamic classes in macros.html form_button: bg-{{ color }}-600/500
    'bg-green-600', 'hover:bg-green-500',
    'bg-blue-600', 'hover:bg-blue-500',
    'bg-red-600', 'hover:bg-red-500',
    'bg-yellow-600', 'hover:bg-yellow-500',
  ],
  theme: {
    extend: {
      fontFamily: {
        'display': ['DM Serif Display', 'Georgia', 'serif'],
        'sans': ['DM Sans', 'system-ui', 'sans-serif'],
      },
      colors: {
        'golf-green': {
          50: '#f0fdf4',
          200: '#bbf7d0',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
        },
        'golf-gold': {
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          900: '#78350f',
        },
        'turf': {
          900: '#0a1a0f',
          800: '#0f2517',
          700: '#1a3a25',
        },
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-down': 'slideDown 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          from: { opacity: '0', transform: 'translateY(10px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        slideDown: {
          from: { opacity: '0', maxHeight: '0' },
          to: { opacity: '1', maxHeight: '500px' },
        },
      },
    },
  },
  plugins: [],
}
