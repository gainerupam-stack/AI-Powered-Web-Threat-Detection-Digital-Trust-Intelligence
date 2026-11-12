
import { useEffect, useState } from 'react'
import {
  ShieldCheck, LayoutDashboard, Globe, MessageSquareWarning,
  FileSearch, ShieldAlert, History, Blocks, Settings, Bell,
  Menu, ArrowUpRight, Activity, Lock, AlertTriangle,
  CheckCircle2, ScanSearch, Zap, ChevronRight, RefreshCw,
  X, ExternalLink, Copy, Info, Search, Link as LinkIcon,
  Mail, Phone, Hash, Clock, FileText, Server, Shield,
  Eye, Check, AlertCircle
} from 'lucide-react'

import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  Tooltip, CartesianGrid, PieChart, Pie, Cell
} from 'recharts'

import './App.css'

const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'
).replace(/\/+$/, '')

const navItems = [
  { name: 'Dashboard', icon: LayoutDashboard },
  { name: 'URL Scanner', icon: Globe },
  { name: 'Message Analyzer', icon: MessageSquareWarning },
  { name: 'Investigation Reports', icon: FileSearch },
  { name: 'Threat Intelligence', icon: ShieldAlert },
  { name: 'Scan History', icon: History },
  { name: 'Blockchain Verification', icon: Blocks },
]

const initialReports = [
  {
    id: 'TG-1024',
    target: 'suspicious-login.example.com',
    type: 'URL Scan',
    risk: 82,
    status: 'Malicious',
    date: '2026-11-10',
  },
  {
    id: 'TG-1023',
    target: 'Unknown payment notification',
    type: 'Message Scan',
    risk: 65,
    status: 'Suspicious',
    date: '2026-11-09',
  },
  {
    id: 'TG-1022',
    target: 'https://example.org',
    type: 'URL Scan',
    risk: 12,
    status: 'Safe',
    date: '2026-11-08',
  },
]

function normalizeUrlInput(value) {
  const trimmed = value.trim()

  if (!trimmed) return ''

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }

  return `https://${trimmed}`
}

function formatDate(value) {
  if (!value) return 'Not available'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return value

  return date.toLocaleString()
}

function getRiskLabel(value) {
  if (value === null || value === undefined) return 'Unknown'

  const score = Number(value)

  if (score >= 75) return 'Malicious'
  if (score >= 40) return 'Suspicious'
  return 'Safe'
}

function getRiskClass(value, category) {
  const label = String(category || getRiskLabel(value)).toLowerCase()

  if (
    label.includes('malicious') ||
    label.includes('high risk') ||
    label.includes('critical') ||
    label.includes('danger')
  ) return 'danger'

  if (
    label.includes('suspicious') ||
    label.includes('medium') ||
    label.includes('warning')
  ) return 'warning'

  if (
    label.includes('safe') ||
    label.includes('low risk') ||
    label.includes('benign')
  ) return 'safe'

  return 'warning'
}

function RiskBadge({ status, risk }) {
  const label = status || getRiskLabel(risk)
  const className = getRiskClass(risk, label)

  return (
    <span className={`risk-badge ${className}`}>
      {label}
    </span>
  )
}

function SectionHeading({ title, description, action }) {
  return (
    <div className="section-heading">
      <div>
        <h3>{title}</h3>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  )
}

function EmptyState({ icon: Icon = FileSearch, title, description }) {
  return (
    <div className="empty-state">
      <Icon size={34} />
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  )
}

async function createAnalysis(payload) {
  const response = await fetch(`${API_BASE}/api/v1/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ...payload,
      include_threat_intel: false,
      register_on_chain: false,
    }),
  })

  const responseText = await response.text()

  let data

  try {
    data = responseText ? JSON.parse(responseText) : {}
  } catch {
    throw new Error('The backend returned an invalid response.')
  }

  if (!response.ok) {
    const detail = typeof data.detail === 'string'
      ? data.detail
      : 'Backend analysis failed.'

    throw new Error(detail)
  }

  return data
}

function DetailRow({ label, value }) {
  if (value === undefined || value === null || value === '') return null

  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  )
}

function SeverityBadge({ severity }) {
  const value = String(severity || 'unknown').toLowerCase()

  const className =
    value === 'high' || value === 'critical'
      ? 'danger'
      : value === 'medium'
        ? 'warning'
        : value === 'low'
          ? 'safe'
          : 'warning'

  return (
    <span className={`risk-badge ${className}`}>
      {severity || 'Unknown'}
    </span>
  )
}

function ReportMetadata({ report }) {
  return (
    <div className="report-metadata">
      <DetailRow label="Report ID" value={report.report_id} />
      <DetailRow label="Created" value={formatDate(report.created_at)} />
      <DetailRow label="Revision" value={report.revision} />
      <DetailRow label="Schema version" value={report.schema_version} />
      {report.report_hash && (
        <div className="detail-row hash-row">
          <span>Report hash</span>
          <code>{report.report_hash}</code>
        </div>
      )}
    </div>
  )
}

function AnalysisReport({ report, type, target }) {
  if (!report) return null

  const findings = report.findings || {}
  const aiRaw = findings.ai_analysis?.raw || {}
  const messageRaw = aiRaw.message_analysis || {}
  const urlRaw = findings.url_tls?.raw || {}
  const urlAnalysis = urlRaw.url_analysis || {}
  const risk = report.risk_score
  const riskClass = getRiskClass(risk, report.risk_category)

  const isMessage = type === 'message'

  const scanFailed =
    (isMessage && (
      aiRaw.status === 'error' ||
      aiRaw.status === 'failed'
    )) ||
    (!isMessage && (
      urlRaw.status === 'failed' ||
      urlAnalysis.valid === false
    ))

  const limitations = [
    ...(Array.isArray(urlRaw.limitations) ? urlRaw.limitations : []),
    ...(Array.isArray(aiRaw.limitations) ? aiRaw.limitations : []),
  ]

  const indicators = Array.isArray(messageRaw.scam_indicators)
    ? messageRaw.scam_indicators
    : []

  const recommendations = Array.isArray(messageRaw.recommendations)
    ? messageRaw.recommendations
    : []

  const extracted = aiRaw.extracted_indicators || {}

  const rationale = Array.isArray(report.rationale)
    ? report.rationale
    : []

  const hasMessageAnalysis = Boolean(
    messageRaw.summary ||
    messageRaw.classification ||
    indicators.length ||
    recommendations.length
  )

  const hasUrlAnalysis = Boolean(
    urlAnalysis.hostname ||
    urlAnalysis.normalized_url ||
    urlRaw.status === 'completed'
  )

  const hasDetailedAnalysis = isMessage
    ? hasMessageAnalysis
    : hasUrlAnalysis

  const scoreText =
    risk === null || risk === undefined
      ? 'N/A'
      : `${risk}/100`

  return (
    <div className="analysis-report">

      {/* Overall verdict */}
      <div className={`report-verdict ${riskClass}`}>
        <div className="report-verdict-main">
          <div className="report-verdict-icon">
            {scanFailed
              ? <AlertTriangle size={26} />
              : riskClass === 'safe'
                ? <ShieldCheck size={26} />
                : <ShieldAlert size={26} />
            }
          </div>

          <div>
            <span className="report-eyebrow">ANALYSIS RESULT</span>
            <h2>
              {scanFailed
                ? 'Scan Incomplete'
                : report.risk_category || 'Analysis Completed'
              }
            </h2>
            <p>
              {scanFailed
                ? 'The backend could not complete this scan. Do not treat this result as safe.'
                : isMessage
                  ? 'Message security analysis'
                  : 'Website security analysis'
              }
            </p>
          </div>
        </div>

        <div className="report-score">
          <span>Risk score</span>
          <strong>{scanFailed ? 'N/A' : scoreText}</strong>
          {!scanFailed && (
            <RiskBadge
              status={report.risk_category}
              risk={risk}
            />
          )}
        </div>
      </div>

      {/* Target */}
      <div className="report-section">
        <SectionHeading
          title="Submitted Input"
          description="The content submitted for security analysis."
        />

        <div className="report-target">
          <span>{isMessage ? 'Message' : 'URL'}</span>
          <p>{target || 'Not available'}</p>
        </div>
      </div>

      {/* Scan failure */}
      {scanFailed && (
        <div className="report-warning">
          <AlertTriangle size={20} />
          <div>
            <strong>Analysis could not be completed</strong>
            <p>
              This result is inconclusive. A zero risk score does not
              mean the submitted content is safe when the scan fails.
            </p>
          </div>
        </div>
      )}

      {/* Message analysis */}
      {isMessage && (
        <>
          <div className="report-section">
            <SectionHeading
              title="AI Message Analysis"
              description="AI-generated classification and explanation."
            />

            {hasMessageAnalysis ? (
              <div className="report-info-card">
                <div className="report-info-top">
                  <div>
                    <span className="report-eyebrow">CLASSIFICATION</span>
                    <h3>
                      {messageRaw.classification || 'Not available'}
                    </h3>
                  </div>

                  {messageRaw.confidence && (
                    <span className="confidence-badge">
                      {String(messageRaw.confidence).toUpperCase()} CONFIDENCE
                    </span>
                  )}
                </div>

                <p className="report-summary">
                  {messageRaw.summary || 'No summary was returned.'}
                </p>
              </div>
            ) : (
              <EmptyState
                icon={Info}
                title="AI analysis unavailable"
                description="The backend did not return detailed message analysis."
              />
            )}
          </div>

          <div className="report-section">
            <SectionHeading
              title="Detected Scam Indicators"
              description={`${indicators.length} indicator(s) identified.`}
            />

            {indicators.length > 0 ? (
              <div className="indicator-list">
                {indicators.map((item, index) => (
                  <div className="indicator-card" key={index}>
                    <div className="indicator-card-top">
                      <div className="indicator-title">
                        <AlertTriangle size={17} />
                        <strong>
                          {item.indicator || 'Suspicious indicator'}
                        </strong>
                      </div>
                      <SeverityBadge severity={item.severity} />
                    </div>

                    {item.evidence && (
                      <div className="indicator-evidence">
                        <span>Evidence</span>
                        <p>{item.evidence}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={ShieldCheck}
                title="No indicators returned"
                description="No scam indicators were provided by the AI analysis. This alone does not guarantee the message is safe."
              />
            )}
          </div>

          <div className="report-section">
            <SectionHeading
              title="Security Recommendations"
              description="Suggested actions based on the analysis."
            />

            {recommendations.length > 0 ? (
              <div className="recommendation-list">
                {recommendations.map((item, index) => (
                  <div className="recommendation-item" key={index}>
                    <CheckCircle2 size={18} />
                    <p>{item}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="muted-text">
                No specific recommendations were returned.
              </p>
            )}
          </div>

          <div className="report-section">
            <SectionHeading
              title="Extracted Indicators"
              description="Contact details and links detected in the message."
            />

            <div className="extracted-grid">
              {[
                {
                  label: 'URLs',
                  icon: LinkIcon,
                  items: extracted.urls,
                },
                {
                  label: 'Email addresses',
                  icon: Mail,
                  items: extracted.emails,
                },
                {
                  label: 'Phone numbers',
                  icon: Phone,
                  items: extracted.phone_numbers,
                },
              ].map((group) => (
                <div className="extracted-card" key={group.label}>
                  <div className="extracted-card-heading">
                    <group.icon size={17} />
                    <span>{group.label}</span>
                  </div>

                  {Array.isArray(group.items) && group.items.length > 0 ? (
                    group.items.map((item, index) => (
                      <p key={index}>{String(item)}</p>
                    ))
                  ) : (
                    <span className="muted-text">None detected</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* URL analysis */}
      {!isMessage && (
        <>
          <div className="report-section">
            <SectionHeading
              title="Website Information"
              description="Domain and URL information returned by the scanner."
            />

            {hasUrlAnalysis ? (
              <div className="report-info-card">
                <DetailRow
                  label="Submitted URL"
                  value={urlAnalysis.submitted_url || target}
                />
                <DetailRow
                  label="Normalized URL"
                  value={urlAnalysis.normalized_url || 'Not available'}
                />
                <DetailRow
                  label="Hostname"
                  value={urlAnalysis.hostname}
                />
                <DetailRow
                  label="Registered domain"
                  value={urlAnalysis.registered_domain}
                />
                <DetailRow
                  label="URL valid"
                  value={
                    urlAnalysis.valid === undefined
                      ? 'Not available'
                      : urlAnalysis.valid ? 'Yes' : 'No'
                  }
                />
              </div>
            ) : (
              <EmptyState
                icon={Globe}
                title="Website information unavailable"
                description="The backend did not return complete URL analysis details."
              />
            )}
          </div>

          <div className="report-section">
            <SectionHeading
              title="Security Findings"
              description="Technical findings from the URL security checks."
            />

            <div className="report-info-card">
              {Object.entries(urlRaw).map(([key, value]) => {
                if (
                  key === 'url_analysis' ||
                  key === 'limitations' ||
                  key === 'status' ||
                  value === null ||
                  value === undefined
                ) return null

                if (typeof value === 'object') {
                  return (
                    <div className="detail-row" key={key}>
                      <span>{key.replaceAll('_', ' ')}</span>
                      <code>
                        {JSON.stringify(value)}
                      </code>
                    </div>
                  )
                }

                return (
                  <DetailRow
                    key={key}
                    label={key.replaceAll('_', ' ')}
                    value={String(value)}
                  />
                )
              })}

              {rationale.length > 0 && (
                <div className="report-rationale">
                  <strong>Risk rationale</strong>
                  {rationale.map((item, index) => (
                    <p key={index}>• {item}</p>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="report-section">
            <SectionHeading
              title="Threat Intelligence"
              description="External threat intelligence status."
            />

            <div className="report-warning">
              <Info size={20} />
              <div>
                <strong>Threat intelligence not requested</strong>
                <p>
                  External threat intelligence checks were disabled for
                  this scan. No clean reputation result should be inferred
                  from this section.
                </p>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Limitations */}
      {limitations.length > 0 && (
        <div className="report-section">
          <SectionHeading
            title="Scan Limitations"
            description="Important limitations affecting this result."
          />

          <div className="report-warning">
            <AlertTriangle size={20} />
            <div>
              {limitations.map((item, index) => (
                <p key={index}>{item}</p>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Report rationale */}
      {rationale.length > 0 && isMessage && (
        <div className="report-section">
          <SectionHeading
            title="Risk Assessment Details"
            description="Factors contributing to the overall risk score."
          />

          <div className="recommendation-list">
            {rationale.map((item, index) => (
              <div className="recommendation-item" key={index}>
                <AlertCircle size={18} />
                <p>{item}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Metadata */}
      <div className="report-section">
        <SectionHeading
          title="Report Information"
          description="Technical metadata for this investigation."
        />
        <ReportMetadata report={report} />
      </div>
    </div>
  )
}

function App() {
  const [page, setPage] = useState('Dashboard')
  const [mobileOpen, setMobileOpen] = useState(false)

  const [url, setUrl] = useState('')
  const [message, setMessage] = useState('')

  const [scanning, setScanning] = useState(false)
  const [urlResult, setUrlResult] = useState(null)
  const [messageResult, setMessageResult] = useState(null)

  const [reports, setReports] = useState(() => {
    try {
      const savedReports = localStorage.getItem('trustguard_reports')
      return savedReports ? JSON.parse(savedReports) : initialReports
    } catch {
      return initialReports
    }
  })

  const [toast, setToast] = useState('')
  const [hash, setHash] = useState('')
  const [verified, setVerified] = useState(null)

  useEffect(() => {
    try {
      localStorage.setItem('trustguard_reports', JSON.stringify(reports))
    } catch (error) {
      console.error('Could not save scan history:', error)
    }
  }, [reports])

  function notify(text) {
    setToast(text)
    window.setTimeout(() => setToast(''), 3500)
  }

  function addReport(data) {
    setReports((previous) => [
      {
        id: data.report_id || `TG-${Date.now()}`,
        target: data.target,
        type: data.type,
        risk: data.risk_score,
        status: data.risk_category || 'Inconclusive',
        date: data.created_at || new Date().toISOString(),
        report: data,
      },
      ...previous,
    ])
  }

  async function runUrlScan(event) {
    event?.preventDefault()

    const submitted = url.trim()

    if (!submitted) {
      notify('Please enter a website URL.')
      return
    }

    const normalized = normalizeUrlInput(submitted)

    setScanning(true)
    setUrlResult(null)

    try {
      const data = await createAnalysis({
        url: normalized,
      })

      const result = {
        ...data,
        target: submitted,
      }

      setUrlResult(result)

      addReport({
        ...data,
        target: submitted,
        type: 'URL Scan',
      })

      notify('URL analysis completed.')
    } catch (error) {
      notify(error.message || 'URL scan failed.')
    } finally {
      setScanning(false)
    }
  }

  async function runMessageScan(event) {
    event?.preventDefault()

    const submitted = message.trim()

    if (!submitted) {
      notify('Please enter a message to analyze.')
      return
    }

    setScanning(true)
    setMessageResult(null)

    try {
      const data = await createAnalysis({
        message: submitted,
      })

      const aiStatus = data.findings?.ai_analysis?.raw?.status

      if (aiStatus === 'error' || aiStatus === 'failed') {
        throw new Error(
          data.findings?.ai_analysis?.raw?.message ||
          'The AI message analysis could not be completed.'
        )
      }

      const result = {
        ...data,
        target: submitted,
      }

      setMessageResult(result)

      addReport({
        ...data,
        target: submitted.length > 100
          ? `${submitted.slice(0, 100)}...`
          : submitted,
        type: 'Message Scan',
      })

      notify('Message analysis completed.')
    } catch (error) {
      notify(error.message || 'Message analysis failed.')
    } finally {
      setScanning(false)
    }
  }

  function copyText(value) {
    if (!value) return

    navigator.clipboard.writeText(String(value))
      .then(() => notify('Copied to clipboard.'))
      .catch(() => notify('Could not copy text.'))
  }

  function navigateTo(nextPage) {
    setPage(nextPage)
    setMobileOpen(false)
  }

  function Dashboard() {
    const totalScans = reports.length
    const maliciousCount = reports.filter((item) =>
      getRiskClass(item.risk, item.status) === 'danger'
    ).length

    const safeCount = reports.filter((item) =>
      getRiskClass(item.risk, item.status) === 'safe'
    ).length

    const suspiciousCount = reports.filter((item) =>
      getRiskClass(item.risk, item.status) === 'warning'
    ).length

    const chartData = [
      { name: 'Mon', scans: 12 },
      { name: 'Tue', scans: 18 },
      { name: 'Wed', scans: 15 },
      { name: 'Thu', scans: 25 },
      { name: 'Fri', scans: 21 },
      { name: 'Sat', scans: 32 },
      { name: 'Sun', scans: 28 },
    ]

    const pieData = [
      { name: 'Safe', value: safeCount || 1 },
      { name: 'Suspicious', value: suspiciousCount || 1 },
      { name: 'Malicious', value: maliciousCount || 1 },
    ]

    return (
      <>
        <PageHeader
          title="Security Dashboard"
          subtitle="Monitor threats, analyze suspicious content and protect your digital environment."
        />

        {/* Main scan actions appear before dashboard statistics */}
        <div className="dashboard-scan-actions">
          <button
            className="dashboard-scan-card url-scan-card"
            onClick={() => navigateTo('URL Scanner')}
          >
            <div className="dashboard-scan-icon">
              <Globe size={25} />
            </div>
            <div className="dashboard-scan-content">
              <span>WEBSITE SECURITY</span>
              <h3>Scan a URL</h3>
              <p>Check websites for suspicious activity and security risks.</p>
            </div>
            <ArrowUpRight size={21} />
          </button>

          <button
            className="dashboard-scan-card message-scan-card"
            onClick={() => navigateTo('Message Analyzer')}
          >
            <div className="dashboard-scan-icon">
              <MessageSquareWarning size={25} />
            </div>
            <div className="dashboard-scan-content">
              <span>AI-POWERED ANALYSIS</span>
              <h3>Analyze a Message</h3>
              <p>Detect phishing, scams and suspicious message patterns.</p>
            </div>
            <ArrowUpRight size={21} />
          </button>
        </div>

        <div className="stats-grid">
          <StatCard
            icon={ScanSearch}
            label="Total Investigations"
            value={totalScans}
            change="All recorded scans"
            color="blue"
          />
          <StatCard
            icon={ShieldAlert}
            label="Threats Detected"
            value={maliciousCount}
            change="High-risk investigations"
            color="red"
          />
          <StatCard
            icon={AlertTriangle}
            label="Suspicious"
            value={suspiciousCount}
            change="Requires attention"
            color="orange"
          />
          <StatCard
            icon={ShieldCheck}
            label="Safe Results"
            value={safeCount}
            change="Low-risk investigations"
            color="green"
          />
        </div>

        <div className="dashboard-charts">
          <div className="panel chart-panel">
            <SectionHeading
              title="Investigation Activity"
              description="Illustrative weekly activity overview."
            />

            <div className="chart-container">
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#6c63ff" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#6c63ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>

                  <CartesianGrid strokeDasharray="3 3" stroke="#263247" />
                  <XAxis
                    dataKey="name"
                    stroke="#8490a5"
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="#8490a5"
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#111b2b',
                      border: '1px solid #29364a',
                      borderRadius: '10px',
                      color: '#fff',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="scans"
                    stroke="#7770ff"
                    strokeWidth={3}
                    fill="url(#scanGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="panel chart-panel">
            <SectionHeading
              title="Risk Distribution"
              description="Distribution of recorded investigations."
            />

            <div className="chart-container pie-chart-container">
              <ResponsiveContainer width="100%" height={260}>
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={5}
                  >
                    <Cell fill="#28c58b" />
                    <Cell fill="#f5a623" />
                    <Cell fill="#f05252" />
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: '#111b2b',
                      border: '1px solid #29364a',
                      borderRadius: '10px',
                      color: '#fff',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-legend">
              <span><i className="legend-safe" /> Safe</span>
              <span><i className="legend-warning" /> Suspicious</span>
              <span><i className="legend-danger" /> Malicious</span>
            </div>
          </div>
        </div>

        <div className="panel recent-panel">
          <SectionHeading
            title="Recent Investigations"
            description="Your latest security analysis activity."
            action={
              <button
                className="text-button"
                onClick={() => navigateTo('Scan History')}
              >
                View all <ChevronRight size={16} />
              </button>
            }
          />

          <InvestigationTable reports={reports.slice(0, 5)} />
        </div>
      </>
    )
  }

  function URLScanner() {
    return (
      <>
        <PageHeader
          title="URL Scanner"
          subtitle="Analyze websites and identify potentially malicious URLs."
        />

        <div className="scanner-panel">
          <div className="scanner-heading">
            <div className="scanner-icon">
              <Globe size={26} />
            </div>
            <div>
              <h2>Website Security Analysis</h2>
              <p>Enter a website address to start a security investigation.</p>
            </div>
          </div>

          <form onSubmit={runUrlScan}>
            <label htmlFor="url-input">Website URL</label>

            <div className="input-with-icon">
              <LinkIcon size={19} />
              <input
                id="url-input"
                type="text"
                placeholder="example.com or https://example.com"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                disabled={scanning}
              />
            </div>

            <p className="input-hint">
              You can enter a domain directly. HTTPS will be added automatically.
            </p>

            <button
              type="submit"
              className="primary-button"
              disabled={scanning}
            >
              {scanning
                ? <><RefreshCw size={18} className="spin" /> Analyzing URL...</>
                : <><ScanSearch size={18} /> Scan Website</>
              }
            </button>
          </form>

          <div className="scanner-security-note">
            <Lock size={15} />
            <span>Analysis is performed by the TrustGuard AI backend.</span>
          </div>
        </div>

        {urlResult && (
          <AnalysisReport
            report={urlResult}
            type="url"
            target={urlResult.target}
          />
        )}
      </>
    )
  }

  function MessageAnalyzer() {
    return (
      <>
        <PageHeader
          title="Message Analyzer"
          subtitle="Detect phishing attempts, scam messages and suspicious communication using AI."
        />

        <div className="scanner-panel">
          <div className="scanner-heading">
            <div className="scanner-icon">
              <MessageSquareWarning size={26} />
            </div>
            <div>
              <h2>AI Message Analysis</h2>
              <p>Paste a suspicious SMS, email or message below.</p>
            </div>
          </div>

          <form onSubmit={runMessageScan}>
            <label htmlFor="message-input">Message content</label>

            <textarea
              id="message-input"
              className="message-textarea"
              placeholder="Paste the suspicious message here..."
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              disabled={scanning}
              rows={7}
            />

            <div className="message-input-footer">
              <span>{message.length} characters</span>
              <button
                type="button"
                className="text-button"
                onClick={() => setMessage('')}
                disabled={scanning || !message}
              >
                Clear message
              </button>
            </div>

            <button
              type="submit"
              className="primary-button"
              disabled={scanning}
            >
              {scanning
                ? <><RefreshCw size={18} className="spin" /> Analyzing Message...</>
                : <><Zap size={18} /> Analyze Message</>
              }
            </button>
          </form>

          <div className="scanner-security-note">
            <ShieldCheck size={15} />
            <span>AI-powered analysis checks for suspicious language and scam indicators.</span>
          </div>
        </div>

        {messageResult && (
          <AnalysisReport
            report={messageResult}
            type="message"
            target={messageResult.target}
          />
        )}
      </>
    )
  }

  function InvestigationReports() {
    return (
      <>
        <PageHeader
          title="Investigation Reports"
          subtitle="Review your recorded security investigation reports."
        />

        <div className="panel">
          <SectionHeading
            title="All Reports"
            description={`${reports.length} investigation(s) recorded.`}
          />

          <InvestigationTable reports={reports} />
        </div>
      </>
    )
  }

  function ScanHistory() {
    return (
      <>
        <PageHeader
          title="Scan History"
          subtitle="A record of your previous URL and message scans."
        />

        <div className="panel">
          <SectionHeading
            title="Recent Scan Activity"
            description="Your locally stored investigation history."
          />

          <InvestigationTable reports={reports} />
        </div>
      </>
    )
  }

  function ThreatIntelligence() {
    return (
      <>
        <PageHeader
          title="Threat Intelligence"
          subtitle="Threat intelligence integrations and external reputation checks."
        />

        <div className="panel">
          <div className="feature-placeholder">
            <ShieldAlert size={38} />
            <h2>Threat Intelligence Integration</h2>
            <p>
              External threat intelligence checks are currently not enabled
              in the scan request. This section will become available when
              the backend integration is configured.
            </p>
            <span className="status-pill">Not configured</span>
          </div>
        </div>
      </>
    )
  }

  function BlockchainVerification() {
    async function verifyReport(event) {
      event.preventDefault()

      if (!hash.trim()) {
        notify('Enter a report hash first.')
        return
      }

      setVerified(null)

      try {
        const response = await fetch(
          `${API_BASE}/api/v1/reports/verify/${encodeURIComponent(hash.trim())}`
        )

        const data = await response.json()

        if (!response.ok) {
          throw new Error(data.detail || 'Verification failed.')
        }

        setVerified(data)
      } catch (error) {
        notify(error.message || 'Could not verify the report.')
      }
    }

    return (
      <>
        <PageHeader
          title="Blockchain Verification"
          subtitle="Verify the integrity of investigation reports using their report hashes."
        />

        <div className="scanner-panel">
          <div className="scanner-heading">
            <div className="scanner-icon">
              <Blocks size={26} />
            </div>
            <div>
              <h2>Verify Report Integrity</h2>
              <p>Enter a report hash to check its verification status.</p>
            </div>
          </div>

          <form onSubmit={verifyReport}>
            <label htmlFor="hash-input">Report hash</label>

            <div className="input-with-icon">
              <Hash size={19} />
              <input
                id="hash-input"
                type="text"
                placeholder="Enter report hash..."
                value={hash}
                onChange={(event) => setHash(event.target.value)}
              />
            </div>

            <button type="submit" className="primary-button">
              <ShieldCheck size={18} />
              Verify Report
            </button>
          </form>

          {verified && (
            <div className="report-info-card verification-result">
              <h3>Verification Response</h3>
              <pre>{JSON.stringify(verified, null, 2)}</pre>
            </div>
          )}
        </div>
      </>
    )
  }

  function SettingsPage() {
    return (
      <>
        <PageHeader
          title="Settings"
          subtitle="TrustGuard AI application information."
        />

        <div className="panel">
          <div className="feature-placeholder">
            <Settings size={38} />
            <h2>Application Settings</h2>
            <p>
              TrustGuard AI is connected to its configured backend API.
              Additional settings will be available here in a future update.
            </p>
          </div>
        </div>
      </>
    )
  }

  function currentPage() {
    switch (page) {
      case 'Dashboard':
        return <Dashboard />
      case 'URL Scanner':
        return <URLScanner />
      case 'Message Analyzer':
        return <MessageAnalyzer />
      case 'Investigation Reports':
        return <InvestigationReports />
      case 'Threat Intelligence':
        return <ThreatIntelligence />
      case 'Scan History':
        return <ScanHistory />
      case 'Blockchain Verification':
        return <BlockchainVerification />
      case 'Settings':
        return <SettingsPage />
      default:
        return <Dashboard />
    }
  }

  return (
    <div className="app-shell">

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="mobile-overlay"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>
          <div className="brand-text">
            <h2>TrustGuard<span> AI</span></h2>
            <p>SECURITY INTELLIGENCE</p>
          </div>

          <button
            className="mobile-close"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
          >
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const Icon = item.icon

            return (
              <button
                key={item.name}
                className={`nav-item ${page === item.name ? 'active' : ''}`}
                onClick={() => navigateTo(item.name)}
              >
                <Icon size={19} />
                <span>{item.name}</span>
                {page === item.name && (
                  <ChevronRight size={16} className="nav-chevron" />
                )}
              </button>
            )
          })}
        </nav>

        <div className="sidebar-bottom">
          <button
            className={`nav-item ${page === 'Settings' ? 'active' : ''}`}
            onClick={() => navigateTo('Settings')}
          >
            <Settings size={19} />
            <span>Settings</span>
          </button>

          <div className="sidebar-status">
            <span className="status-dot" />
            <span>System operational</span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="menu-button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
            >
              <Menu size={22} />
            </button>

            <div className="breadcrumb">
              <span>TrustGuard AI</span>
              <ChevronRight size={15} />
              <strong>{page}</strong>
            </div>
          </div>

          <div className="topbar-right">
            <div className="system-status">
              <span className="status-dot" />
              <span>System Online</span>
            </div>

            <button
              className="notification-button"
              aria-label="Notifications"
              onClick={() => notify('You are all caught up.')}
            >
              <Bell size={19} />
            </button>

            <div className="user-avatar">TG</div>
          </div>
        </header>

        <div className="page-content">
          {currentPage()}
        </div>
      </main>

      {toast && (
        <div className="toast-message">
          <Info size={17} />
          <span>{toast}</span>
        </div>
      )}
    </div>
  )
}

function PageHeader({ title, subtitle }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
    </div>
  )
}

function StatCard({ icon: Icon, label, value, change, color }) {
  return (
    <div className={`stat-card ${color}`}>
      <div className="stat-card-top">
        <span>{label}</span>
        <div className="stat-icon">
          <Icon size={20} />
        </div>
      </div>
      <h2>{value}</h2>
      <p>{change}</p>
    </div>
  )
}

function InvestigationTable({ reports = [] }) {
  if (!reports.length) {
    return (
      <EmptyState
        icon={FileSearch}
        title="No investigations yet"
        description="Your completed URL and message scans will appear here."
      />
    )
  }

  return (
    <div className="table-wrapper">
      <table className="investigation-table">
        <thead>
          <tr>
            <th>Investigation</th>
            <th>Type</th>
            <th>Risk Score</th>
            <th>Status</th>
            <th>Date</th>
          </tr>
        </thead>

        <tbody>
          {reports.map((report, index) => (
            <tr key={report.id || index}>
              <td>
                <div className="table-target">
                  <span className="table-target-icon">
                    {report.type === 'URL Scan'
                      ? <Globe size={16} />
                      : <MessageSquareWarning size={16} />
                    }
                  </span>
                  <span>{report.target}</span>
                </div>
              </td>

              <td>{report.type}</td>

              <td>
                {report.risk === null || report.risk === undefined
                  ? 'N/A'
                  : `${report.risk}/100`
                }
              </td>

              <td>
                <RiskBadge
                  status={report.status}
                  risk={report.risk}
                />
              </td>

              <td>{formatDate(report.date)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default App
