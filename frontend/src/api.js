const BASE = ''

async function request(path, options = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`${res.status} ${res.statusText} ${text}`)
  }
  const ct = res.headers.get('content-type') || ''
  if (ct.includes('application/json')) return res.json()
  return res
}

export const api = {
  health: () => request('/api/health'),
  features: () => request('/api/features'),
  upload: (file, onProgress) =>
    new Promise((resolve, reject) => {
      const form = new FormData()
      form.append('file', file)
      const xhr = new XMLHttpRequest()
      xhr.open('POST', '/api/upload')
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(Math.round((e.loaded / e.total) * 100))
        }
      }
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText))
          } catch (err) {
            reject(err)
          }
        } else {
          reject(new Error(`upload failed: ${xhr.status}`))
        }
      }
      xhr.onerror = () => reject(new Error('upload network error'))
      xhr.send(form)
    }),
  pack: (uploadId, options) =>
    request('/api/pack', {
      method: 'POST',
      body: JSON.stringify({ upload_id: uploadId, options })
    }),
  jobs: () => request('/api/jobs'),
  job: (id) => request(`/api/jobs/${id}`),
  jobLog: (id, tail = 0) => request(`/api/jobs/${id}/log?tail=${tail}`),
  jobReport: (id) => request(`/api/jobs/${id}/report`),
  downloadUrl: (id) => `/api/jobs/${id}/download`,
  logs: () => request('/api/logs'),
  readLog: (id, tail = 500) => request(`/api/logs/${id}?tail=${tail}`),
  history: () => request('/api/history'),
  toggles: () => request('/api/toggles'),
  addToggle: (feature, enabled, source = 'ui') =>
    request('/api/toggles', {
      method: 'POST',
      body: JSON.stringify({ feature, enabled, source })
    }),
  settings: () => request('/api/settings'),
  saveSettings: (payload) =>
    request('/api/settings', { method: 'PUT', body: JSON.stringify(payload) })
}

export function subscribeJob(jobId, onRecord, onDone) {
  const es = new EventSource(`/api/jobs/${jobId}/stream`)
  es.onmessage = (ev) => {
    try {
      const rec = JSON.parse(ev.data)
      if (rec.message === '__job_closed__') {
        es.close()
        if (onDone) onDone(rec.status)
        return
      }
      onRecord(rec)
    } catch (err) {
      /* ignore malformed frame */
    }
  }
  es.onerror = () => {
    es.close()
  }
  return () => es.close()
}
