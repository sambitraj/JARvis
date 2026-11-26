import React, { useEffect, useMemo, useRef, useState } from 'react'
import { health, getJob, uploadProject, scanGithub, remediate, reportUrl, downloadUrl } from './api.js'

const SEV = {
  CRITICAL: { bar: 'bg-red-700', pill: 'bg-red-700 text-white' },
  HIGH: { bar: 'bg-orange-500', pill: 'bg-orange-600 text-white' },
  MEDIUM: { bar: 'bg-amber-400', pill: 'bg-amber-300 text-ink' },
  LOW: { bar: 'bg-sky-400', pill: 'bg-sky-200 text-ink' },
  UNKNOWN: { bar: 'bg-slate-300', pill: 'bg-slate-200 text-ink' },
}
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const STATUS = {
  pending: ['Planned', 'bg-slate-100 text-slate-700'],
  fixed: ['Fixed and validated', 'bg-emerald-100 text-emerald-800'],
  fixed_unvalidated: ['Fixed', 'bg-amber-100 text-amber-800'],
  awaiting_approval: ['Needs approval', 'bg-orange-100 text-orange-800'],
  no_fix: ['No safe version', 'bg-slate-100 text-slate-500'],
  rejected_build_failed: ['Rejected: build failed', 'bg-red-100 text-red-800'],
  baseline_failing: ['Skipped: build failing', 'bg-red-100 text-red-800'],
  not_selected: ['Not selected', 'bg-slate-100 text-slate-500'],
}
const STAGES = [['scan', 'Scan'], ['resolve', 'Safe versions'], ['ai', 'AI impact'], ['review', 'Review'], ['validate', 'Build and test'], ['report', 'Report']]
const ICON = {
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z',
  upload: 'M12 16V4m0 0L8 8m4-4l4 4M4 20h16',
  download: 'M12 4v12m0 0l-4-4m4 4l4-4M4 20h16',
  search: 'M21 21l-4.3-4.3M17 10.5a6.5 6.5 0 11-13 0 6.5 6.5 0 0113 0z',
  check: 'M5 13l4 4L19 7',
  alert: 'M12 9v4m0 4h.01M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z',
  chevron: 'M6 9l6 6 6-6',
  file: 'M7 3h7l5 5v13H7zM14 3v5h5',
  branch: 'M6 3v12m0 0a3 3 0 100 6 3 3 0 000-6zm12-6a3 3 0 100-6 3 3 0 000 6zm0 0c0 4-6 3-12 6',
}

function Icon({ name, className = 'h-5 w-5' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={ICON[name]} />
    </svg>
  )
}

function Pill({ children, tone = 'bg-brandsoft text-brand' }) {
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${tone}`}>{children}</span>
}

function Header({ info }) {
  return (
    <header className="border-b border-line bg-white">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-5 py-4">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand text-white"><Icon name="shield" /></span>
          <div>
            <h1 className="font-display text-2xl font-bold leading-none tracking-tight">JAR<span className="text-java">vis</span> AI</h1>
            <p className="text-xs text-slate-500">Java dependency vulnerability remediation</p>
          </div>
        </div>
        {info && (
          <div className="flex flex-wrap gap-2">
            <Pill tone={info.openai_configured ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}>
              {info.openai_configured ? `AI: ${info.model}` : 'AI: rule-based (no key)'}
            </Pill>
          </div>
        )}
      </div>
    </header>
  )
}

function Landing({ onFile, onUrl, busy }) {
  const [over, setOver] = useState(false)
  const [url, setUrl] = useState('')
  const ref = useRef()
  const steps = [['Scan', 'Find vulnerable libraries'], ['Resolve', 'Pick the safest version'], ['Fix', 'Update pom.xml under policy'], ['Prove', 'Build and test in isolation']]
  return (
    <div className="space-y-10">
      <div className="max-w-2xl">
        <h2 className="font-display text-4xl font-bold leading-tight tracking-tight">Fix vulnerable dependencies, and prove nothing broke.</h2>
        <p className="mt-3 text-slate-600">Upload a Maven project or paste a GitHub link. JARvis finds the risky libraries, picks safe versions, applies low-risk fixes and tests every change in a separate copy.</p>
      </div>
      <div className="grid gap-5 md:grid-cols-2">
        <div
          onDragOver={(e) => { e.preventDefault(); setOver(true) }} onDragLeave={() => setOver(false)}
          onDrop={(e) => { e.preventDefault(); setOver(false); e.dataTransfer.files[0] && onFile(e.dataTransfer.files[0]) }}
          className={`flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center transition-colors ${over ? 'border-brand bg-brandsoft' : 'border-line bg-white'}`}>
          <span className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-brandsoft text-brand"><Icon name="upload" className="h-6 w-6" /></span>
          <p className="font-display text-lg font-semibold">Upload a project</p>
          <p className="mt-1 text-sm text-slate-500">Drop a .zip or a pom.xml here</p>
          <button disabled={busy} onClick={() => ref.current.click()} className="mt-5 rounded-lg bg-brand px-5 py-2 text-sm font-semibold text-white hover:bg-teal-900 disabled:opacity-50">
            {busy ? 'Working…' : 'Choose file'}
          </button>
          <input ref={ref} type="file" accept=".zip,.xml" hidden onChange={(e) => e.target.files[0] && onFile(e.target.files[0])} />
        </div>
        <div className="flex flex-col justify-center rounded-2xl border border-line bg-white p-8">
          <span className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 text-java"><Icon name="branch" className="h-6 w-6" /></span>
          <p className="font-display text-lg font-semibold">Scan a GitHub repository</p>
          <p className="mt-1 text-sm text-slate-500">Public repositories only</p>
          <div className="mt-5 flex gap-2">
            <input value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && url.trim() && onUrl(url.trim())}
              placeholder="https://github.com/owner/repo" aria-label="GitHub repository URL"
              className="min-w-0 flex-1 rounded-lg border border-line px-3 py-2 text-sm" />
            <button disabled={busy || !url.trim()} onClick={() => onUrl(url.trim())}
              className="rounded-lg bg-java px-4 py-2 text-sm font-semibold text-white hover:bg-amber-700 disabled:opacity-50">Scan</button>
          </div>
        </div>
      </div>
      <ol className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {steps.map(([t, d], i) => (
          <li key={t} className="flex gap-3">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-ink font-display text-sm font-bold text-white">{i + 1}</span>
            <div><p className="font-semibold">{t}</p><p className="text-sm text-slate-500">{d}</p></div>
          </li>
        ))}
      </ol>
    </div>
  )
}

function Progress({ job }) {
  const idx = Math.max(0, STAGES.findIndex(([k]) => k === job.stage || (job.stage === 'remediate' && k === 'validate')))
  const done = job.status === 'completed'
  const active = ['queued', 'scanning', 'remediating'].includes(job.status)
  return (
    <div className="rounded-2xl border border-line bg-white p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="font-display text-lg font-semibold">{job.filename}</p>
          <p className="font-mono text-xs text-slate-500">job {job.id}</p>
        </div>
        <Pill tone={job.status === 'failed' ? 'bg-red-100 text-red-800' : done ? 'bg-emerald-100 text-emerald-800' : 'bg-brandsoft text-brand'}>{job.status}</Pill>
      </div>
      <ol className="mt-5 grid grid-cols-3 gap-y-3 sm:grid-cols-6">
        {STAGES.map(([k, label], i) => {
          const st = done || i < idx ? 'done' : i === idx && job.status !== 'failed' ? 'now' : 'todo'
          return (
            <li key={k} className="flex flex-col items-center gap-1.5 text-center">
              <span className={`flex h-7 w-7 items-center justify-center rounded-full text-xs font-bold ${st === 'done' ? 'bg-brand text-white' : st === 'now' ? 'bg-java text-white ring-4 ring-amber-100' : 'bg-slate-100 text-slate-400'}`}>
                {st === 'done' ? <Icon name="check" className="h-4 w-4" /> : i + 1}
              </span>
              <span className={`text-xs ${st === 'todo' ? 'text-slate-400' : 'font-medium text-ink'}`}>{label}</span>
            </li>
          )
        })}
      </ol>
      {active && (
        <div className="mt-4">
          <div className="h-1 overflow-hidden rounded bg-brandsoft"><div className="h-full w-1/3 animate-pulse rounded bg-brand" /></div>
          <p className="mt-2 text-sm text-slate-600">{job.events.at(-1)?.msg || 'Working…'}</p>
        </div>
      )}
    </div>
  )
}

function Summary({ s }) {
  const cards = [['Scanned', s.dependencies_scanned, 'text-ink'], ['Vulnerable', s.vulnerable, 'text-red-700'], ['Auto-fix ready', s.auto_eligible, 'text-brand'], ['Need approval', s.needs_approval, 'text-java'], ['Fixed', s.fixed, 'text-emerald-700']]
  const sev = s.severity || {}
  const total = SEV_ORDER.reduce((n, k) => n + (sev[k] || 0), 0) || 1
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {cards.map(([k, v, c]) => (
          <div key={k} className="rounded-2xl border border-line bg-white p-4">
            <dd className={`font-display text-3xl font-bold ${c}`}>{v ?? 0}</dd>
            <dt className="text-xs text-slate-500">{k}</dt>
          </div>
        ))}
      </dl>
      <div className="rounded-2xl border border-line bg-white p-4">
        <div className="flex h-3 overflow-hidden rounded-full bg-slate-100">
          {SEV_ORDER.filter((k) => sev[k]).map((k) => <div key={k} className={SEV[k].bar} style={{ width: `${(sev[k] / total) * 100}%` }} title={`${k}: ${sev[k]}`} />)}
        </div>
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-600">
          {SEV_ORDER.filter((k) => sev[k]).map((k) => <span key={k} className="flex items-center gap-1.5"><span className={`h-2.5 w-2.5 rounded-full ${SEV[k].bar}`} />{k.toLowerCase()} {sev[k]}</span>)}
        </div>
      </div>
    </div>
  )
}

function Row({ f, selected, onToggle, locked, choice, onChoose }) {
  const [open, setOpen] = useState(false)
  const chosen = choice || f.target || ''
  const options = (f.options || []).filter((o) => o.safe) // vulnerable versions are never offered
  const opt = options.find((o) => o.version === chosen)
  const ctype = opt?.change_type || f.change_type
  const [label, tone] = STATUS[f.status] || [f.status, 'bg-slate-100 text-slate-700']
  const a = f.analysis
  return (
    <li className="border-b border-line last:border-0">
      <div className="flex flex-wrap items-center gap-3 px-4 py-3">
        <input type="checkbox" className="h-4 w-4 accent-teal-700" disabled={!chosen || locked} checked={selected} onChange={onToggle} aria-label={`Select ${f.artifact}`} />
        <span className={`w-1.5 self-stretch rounded ${(SEV[f.severity] || SEV.UNKNOWN).bar}`} />
        <button onClick={() => setOpen(!open)} aria-expanded={open} className="min-w-0 flex-1 text-left">
          <span className="block truncate font-mono text-sm font-medium">{f.group}:{f.artifact}</span>
          <span className="text-xs text-slate-500">{f.severity.toLowerCase()} · {f.vulns.length} advisories · {f.pom_path}</span>
        </button>
        <span className="flex items-center gap-1.5 font-mono text-sm">{f.current} <span className="text-slate-400">→</span>
          {options.length > 0 ? (
            <select value={chosen} disabled={locked} onChange={(e) => onChoose(e.target.value)} aria-label={`Target version for ${f.artifact}`}
              className="w-80 max-w-full rounded-md border border-line bg-white px-2 py-1 text-xs">
              {!chosen && <option value="">Choose version…</option>}
              {options.map((o) => (
                <option key={o.version} value={o.version}>{`${o.version} · ${o.change_type}${o.version === f.suggested ? ' · ★ recommended' : ''}`}</option>
              ))}
            </select>
          ) : <b>{f.target || 'n/a'}</b>}
        </span>
        {ctype && <Pill tone={ctype === 'major' ? 'bg-red-100 text-red-800' : 'bg-brandsoft text-brand'}>{ctype}</Pill>}
        {f.target && (!choice || choice === f.suggested) && <Pill tone={f.auto_eligible ? 'bg-emerald-100 text-emerald-800' : 'bg-orange-100 text-orange-800'}>{f.auto_eligible ? 'auto' : 'approval'}</Pill>}
        <Pill tone={tone}>{label}</Pill>
        <button onClick={() => setOpen(!open)} aria-label="Details" className="text-slate-400 hover:text-ink"><Icon name="chevron" className={`h-5 w-5 transition-transform ${open ? 'rotate-180' : ''}`} /></button>
      </div>
      {open && (
        <div className="space-y-4 bg-paper px-5 py-4 text-sm">
          {f.policy_reason && <p><b>Policy:</b> {f.policy_reason}</p>}
          <div>
            <h4 className="mb-1 font-semibold">Advisories</h4>
            <ul className="space-y-1">
              {f.vulns.map((v) => (
                <li key={v.id}>
                  <a className="font-mono text-brand underline" href={v.url} target="_blank" rel="noreferrer">{v.cve || v.id}</a>{' '}
                  <Pill tone={(SEV[v.severity] || SEV.UNKNOWN).pill}>{v.severity}</Pill> <span className="text-slate-600">{v.summary}</span>
                </li>
              ))}
            </ul>
          </div>
          {a && (
            <div>
              <h4 className="mb-1 font-semibold">Code impact <span className="font-normal text-slate-500">({a.source}, risk {a.risk_level})</span></h4>
              <p>{a.summary}</p>
              {a.breaking_changes?.length > 0 && <ul className="mt-2 list-disc pl-5">{a.breaking_changes.map((b, i) => <li key={i}>{b}</li>)}</ul>}
              {a.affected_files?.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {a.affected_files.map((x, i) => <li key={i}><span className="font-mono text-xs">{x.file}</span>: {x.reason}{x.suggested_change ? ` → ${x.suggested_change}` : ''}</li>)}
                </ul>
              )}
              <p className="mt-2 text-xs text-slate-500">AI suggestions are advisory. JARvis only changes the POM.</p>
            </div>
          )}
        </div>
      )}
    </li>
  )
}

function Findings({ job, selected, setSelected, ready, choices, setChoices }) {
  const [q, setQ] = useState('')
  const [sev, setSev] = useState('ALL')
  const [fixable, setFixable] = useState(false)
  const term = q.trim().toLowerCase()
  const shown = useMemo(() => job.findings.filter((f) =>
    (sev === 'ALL' || f.severity === sev) && (!fixable || f.target) &&
    (!term || `${f.group}:${f.artifact}`.toLowerCase().includes(term) || f.vulns.some((v) => (v.cve || v.id).toLowerCase().includes(term)))), [job.findings, sev, fixable, term])
  const toggle = (id) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]))
  const chips = ['ALL', ...SEV_ORDER.filter((k) => job.findings.some((f) => f.severity === k))]
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="font-display text-xl font-semibold">Findings</h2>
          <p className="max-w-2xl text-sm text-slate-600">Search and tick the libraries you want fixed, or let JARvis auto-fix everything low-risk. Use the dropdown to pick a different version (★ recommended; only versions without known vulnerabilities are listed). Major upgrades need you to tick them.</p>
        </div>
        <div className="flex gap-4 text-sm">
          <button className="text-brand underline" onClick={() => setSelected((s) => [...new Set([...s, ...shown.filter((f) => f.target).map((f) => f.id)])])}>Select all shown</button>
          <button className="text-brand underline" onClick={() => setSelected([])}>Clear</button>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <label className="relative min-w-[16rem] flex-1">
          <span className="pointer-events-none absolute left-3 top-2.5 text-slate-400"><Icon name="search" className="h-4 w-4" /></span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search dependencies"
            placeholder="Search library or CVE, e.g. jackson or CVE-2021-44228"
            className="w-full rounded-lg border border-line bg-white py-2 pl-9 pr-3 text-sm" />
        </label>
        <div className="flex flex-wrap gap-1.5">
          {chips.map((k) => (
            <button key={k} onClick={() => setSev(k)} className={`rounded-full border px-3 py-1 text-xs font-semibold ${sev === k ? 'border-ink bg-ink text-white' : 'border-line bg-white text-slate-600 hover:border-slate-400'}`}>
              {k === 'ALL' ? 'All' : k.charAt(0) + k.slice(1).toLowerCase()}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1.5 text-xs text-slate-600"><input type="checkbox" className="accent-teal-700" checked={fixable} onChange={(e) => setFixable(e.target.checked)} /> Fixable only</label>
      </div>
      <p className="text-xs text-slate-500">{shown.length} of {job.findings.length} shown · {selected.length} selected</p>
      <ul className="overflow-hidden rounded-2xl border border-line bg-white">
        {shown.length === 0 && <li className="px-4 py-8 text-center text-sm text-slate-500">No dependencies match your search.</li>}
        {shown.map((f) => <Row key={f.id} f={f} selected={selected.includes(f.id)} onToggle={() => toggle(f.id)} locked={!ready} choice={choices[f.id]}
          onChoose={(v) => { setChoices((c) => ({ ...c, [f.id]: v })); if (v) setSelected((s) => (s.includes(f.id) ? s : [...s, f.id])) }} />)}
      </ul>
    </section>
  )
}

function Results({ job }) {
  const r = job.remediation
  const runs = (r?.validations || []).filter((v) => v.status !== 'skipped') // hide the 'skipped' row when validation is off
  if (!runs.length) return null
  const tone = { passed: 'bg-emerald-100 text-emerald-800', failed: 'bg-red-100 text-red-800', skipped: 'bg-amber-100 text-amber-800', error: 'bg-red-100 text-red-800' }
  return (
    <section className="space-y-3">
      <h2 className="font-display text-xl font-semibold">Build and test validation</h2>
      {runs.map((v, i) => (
        <details key={i} className="rounded-xl border border-line bg-white">
          <summary className="flex cursor-pointer flex-wrap items-center gap-3 px-4 py-3 text-sm">
            <Pill tone={tone[v.status]}>{v.status}</Pill><span className="min-w-0 flex-1 truncate">{v.label}</span>
            <span className="text-xs text-slate-500">{v.mode} · {v.duration}s</span>
          </summary>
          <pre className="max-h-72 overflow-auto rounded-b-xl bg-ink p-3 font-mono text-xs text-slate-100">{v.log_tail}</pre>
        </details>
      ))}
    </section>
  )
}

function Downloads({ id }) {
  const items = [['HTML report', reportUrl(id, 'html'), 'file'], ['Markdown report', reportUrl(id, 'md'), 'file'], ['JSON report', reportUrl(id, 'json'), 'file'],
    ['Updated pom.xml', downloadUrl(id, 'pom'), 'download'], ['Remediated project', downloadUrl(id, 'project'), 'download'], ['Full package (.zip)', downloadUrl(id, 'full'), 'download']]
  return (
    <section>
      <h2 className="mb-3 font-display text-xl font-semibold">Downloads</h2>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {items.map(([l, u, ic]) => (
          <a key={l} href={u} className="flex items-center gap-2 rounded-xl border border-line bg-white px-4 py-3 text-sm font-medium text-brand hover:border-brand hover:bg-brandsoft">
            <Icon name={ic} className="h-4 w-4" />{l}
          </a>
        ))}
      </div>
    </section>
  )
}

export default function App() {
  const [job, setJob] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [info, setInfo] = useState(null)
  const [selected, setSelected] = useState([])
  const [choices, setChoices] = useState({})

  useEffect(() => { health().then(setInfo).catch(() => setErr('Backend not reachable on port 8000.')) }, [])
  const active = job && ['queued', 'scanning', 'remediating'].includes(job.status)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => getJob(job.id).then(setJob).catch((e) => setErr(e.message)), 1500)
    return () => clearInterval(t)
  }, [active, job?.id])

  const start = async (fn, arg) => {
    setErr(''); setBusy(true); setSelected([]); setChoices({})
    try { const { id } = await fn(arg); setJob(await getJob(id)) } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  const run = async (ids, useChoices) => {
    setErr('')
    const overrides = useChoices ? Object.fromEntries(ids.filter((id) => choices[id]).map((id) => [id, choices[id]])) : {}
    try { await remediate(job.id, [], ids, overrides); setJob(await getJob(job.id)) } catch (e) { setErr(e.message) }
  }
  const ready = job && (job.status === 'scanned' || job.status === 'completed')
  const hasFindings = job && job.findings.length > 0

  return (
    <div className="min-h-screen">
      <Header info={info} />
      <main className="mx-auto max-w-6xl space-y-8 px-5 py-8">
        {err && <p role="alert" className="rounded-xl border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-800">{err}</p>}
        {!job && <Landing onFile={(f) => start(uploadProject, f)} onUrl={(u) => start(scanGithub, u)} busy={busy} />}
        {job && (
          <>
            <div className="flex justify-end"><button onClick={() => { setJob(null); setSelected([]); setChoices({}) }} className="text-sm font-medium text-brand underline">Scan another project</button></div>
            <Progress job={job} />
            {job.status === 'failed' && <p role="alert" className="flex items-center gap-2 rounded-xl border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-800"><Icon name="alert" className="h-4 w-4" />{job.error}</p>}
            {job.summary?.dependencies_scanned !== undefined && (
              <>
                <Summary s={job.summary} />
                {!hasFindings
                  ? <p className="rounded-2xl border border-line bg-white p-6">No known vulnerabilities in the direct dependencies of this project.</p>
                  : <Findings job={job} selected={selected} setSelected={setSelected} ready={ready} choices={choices} setChoices={setChoices} />}
              </>
            )}
            <Results job={job} />
            {job.status === 'completed' && <Downloads id={job.id} />}
            <details className="text-sm">
              <summary className="cursor-pointer text-slate-600">Activity log</summary>
              <ul className="mt-2 space-y-0.5 rounded-xl bg-ink p-4 font-mono text-xs text-slate-200">
                {job.events.map((e, i) => <li key={i}><span className="text-slate-500">{e.t}</span> {e.msg}</li>)}
              </ul>
            </details>
            {hasFindings && (
              <div className="sticky bottom-0 z-10 -mx-5 border-t border-line bg-white/95 px-5 py-3 backdrop-blur">
                <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3">
                  <p className="text-sm text-slate-600"><b className="text-ink">{selected.length}</b> selected · <b className="text-ink">{job.summary.auto_eligible}</b> auto-fix ready</p>
                  <div className="flex flex-wrap gap-2">
                    <button onClick={() => run(selected, true)} disabled={!ready || selected.length === 0}
                      className="rounded-lg bg-java px-5 py-2 text-sm font-semibold text-white hover:bg-amber-700 disabled:opacity-40">Fix selected ({selected.length})</button>
                    <button onClick={() => run([], false)} disabled={!ready || !job.summary.auto_eligible}
                      className="rounded-lg bg-brand px-5 py-2 text-sm font-semibold text-white hover:bg-teal-900 disabled:opacity-40">Auto-fix eligible ({job.summary.auto_eligible})</button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  )
}
