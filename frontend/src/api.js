const j = async (r) => {
  if (!r.ok) {
    let msg = r.statusText
    try { msg = (await r.json()).detail || msg } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json()
}

export const health = () => fetch('/api/health').then(j)
export const getJob = (id) => fetch(`/api/jobs/${id}`).then(j)
export const uploadProject = (file) => {
  const fd = new FormData()
  fd.append('file', file)
  return fetch('/api/jobs', { method: 'POST', body: fd }).then(j)
}
export const scanGithub = (url) =>
  fetch('/api/jobs/github', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  }).then(j)
export const remediate = (id, approvedIds, onlyIds = [], overrides = {}) =>
  fetch(`/api/jobs/${id}/remediate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approved_ids: approvedIds, only_ids: onlyIds, overrides }),
  }).then(j)
export const reportUrl = (id, fmt) => `/api/jobs/${id}/reports/${fmt}`
export const downloadUrl = (id, kind) => `/api/jobs/${id}/downloads/${kind}`
