import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/prod/*': {
        target: 'https://d2dk1x8rcuw2g3.cloudfront.net/',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
