import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/analyze': 'http://localhost:8000',
      '/top-templates': 'http://localhost:8000',
      '/in-window': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})
