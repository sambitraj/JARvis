export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        display: ['"Bricolage Grotesque"', 'system-ui', 'sans-serif'],
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      colors: {
        paper: '#F3F5F2', ink: '#14232B', brand: '#0F5C63', brandsoft: '#DCEBEA',
        java: '#C9790B', line: '#D5DBD9',
      },
    },
  },
  plugins: [],
}
