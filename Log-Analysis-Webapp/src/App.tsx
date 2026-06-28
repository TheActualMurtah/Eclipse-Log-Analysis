import { useState } from 'react'
import './App.css'
import type { AnalysisResult, Rule } from './types'
import FileUpload from './components/FileUpload'
import KpiCards from './components/KpiCards'
import TopTemplates from './components/TopTemplates'
import TimeWindowQuery from './components/TimeWindowQuery'
import RuleConfigurator from './components/RuleConfigurator'
import EventFeed from './components/EventFeed'

type Tab = 'overview' | 'templates' | 'window' | 'rules'

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'templates', label: 'Top Templates' },
  { id: 'window', label: 'Time Window' },
  { id: 'rules', label: 'Rules' },
]

export default function App() {
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  async function handleUpload(file: File) {
    setLoading(true)
    setError(null)

    const form = new FormData()
    form.append('file', file)
    // strip client-only `id` field before sending
    const apiRules = rules.map(({ id: _id, ...rest }) => rest)
    form.append('rules', JSON.stringify(apiRules))

    try {
      const res = await fetch('/analyze', { method: 'POST', body: form })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? 'Analysis failed')
      setResult(data)
      setActiveTab('overview')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-900/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">Eclipse Log Analysis</h1>
            <p className="text-xs text-slate-500">Jenkins log analyzer</p>
          </div>
          {result && (
            <span className="text-xs text-slate-500">
              {result.total.toLocaleString()} events parsed
            </span>
          )}
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        {/* Upload */}
        <section>
          <FileUpload onUpload={handleUpload} loading={loading} />
          {error && (
            <p className="mt-3 text-sm text-red-400 bg-red-950/40 border border-red-800 rounded-lg px-4 py-2">
              {error}
            </p>
          )}
        </section>

        {result && (
          <>
            {/* Tabs */}
            <nav className="flex gap-1 bg-slate-800 rounded-xl p-1 w-fit">
              {TABS.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeTab === tab.id
                      ? 'bg-violet-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </nav>

            {/* Tab panels */}
            {activeTab === 'overview' && (
              <section className="space-y-6">
                <KpiCards result={result} />
                <div>
                  <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
                    Fatal &amp; Error Events
                  </h2>
                  <EventFeed events={result.events} fatalOnly />
                </div>
              </section>
            )}

            {activeTab === 'templates' && (
              <section>
                <TopTemplates events={result.events} />
              </section>
            )}

            {activeTab === 'window' && (
              <section>
                <TimeWindowQuery events={result.events} />
              </section>
            )}

            {activeTab === 'rules' && (
              <section className="space-y-4">
                <p className="text-sm text-slate-400">
                  Define rules to ignore noisy events, tag events, or reclassify severity.
                  Rules are applied when you upload or re-upload a log file.
                </p>
                <RuleConfigurator rules={rules} onChange={setRules} />
              </section>
            )}
          </>
        )}

        {!result && !loading && (
          <div className="text-center py-16 text-slate-600">
            <p className="text-4xl mb-3">📋</p>
            <p className="text-sm">Upload a Jenkins log file to get started</p>
          </div>
        )}
      </main>
    </div>
  )
}
