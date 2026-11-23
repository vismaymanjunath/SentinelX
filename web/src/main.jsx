import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'
import './i18n'
import SaasApp from './Saas'
import CollectorApp from './Collector'

function Root() {
  const [who, setWho] = useState(null)
  useEffect(() => { fetch('/api/whoami').then(r => r.json()).then(setWho).catch(() => setWho({ tier: 'saas' })) }, [])
  if (!who) return null
  return who.tier === 'collector' ? <CollectorApp who={who} /> : <SaasApp />
}
createRoot(document.getElementById('root')).render(<Root />)
