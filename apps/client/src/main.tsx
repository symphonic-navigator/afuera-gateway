import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BLOB_VERSION } from '@afuera/crypto'
import './index.css'
import App from './App.tsx'

// Smoke check: proves @afuera/crypto links into the browser bundle.
// Reads a constant only — no crypto runs at startup.
console.info(`@afuera/crypto loaded (blob format v${BLOB_VERSION})`)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
