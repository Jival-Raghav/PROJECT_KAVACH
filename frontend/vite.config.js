import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/run-pipeline': 'http://localhost:8000',
      '/status': 'http://localhost:8000',
      '/users': 'http://localhost:8000',
      '/stats': 'http://localhost:8000',
      '/org-anomalies': 'http://localhost:8000',
      '/llm-status': 'http://localhost:8000',
      '/clusters': 'http://localhost:8000',
      '/feedback': 'http://localhost:8000',
    }
  }
})
