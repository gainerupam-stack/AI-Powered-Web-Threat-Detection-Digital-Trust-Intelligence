import { useEffect, useState } from 'react'
import {
  ShieldCheck, LayoutDashboard, Globe, MessageSquareWarning,
  FileSearch, ShieldAlert, History, Blocks, Settings, Bell,
  Menu, ArrowUpRight, Activity,
  Lock, AlertTriangle, CheckCircle2,
  ScanSearch, Zap, ChevronRight, RefreshCw
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  Tooltip, CartesianGrid, PieChart, Pie, Cell
} from 'recharts'
import './App.css'

const API_BASE =
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'
const navItems = [
  { name: 'Dashboard', icon: LayoutDashboard },
  { name: 'URL Scanner', icon: Globe },
  { name: 'Message Analyzer', icon: MessageSquareWarning },
  { name: 'Investigation Reports', icon: FileSearch },
  { name: 'Threat Intelligence', icon: ShieldAlert },
  { name: 'Scan History', icon: History },
  { name: 'Blockchain Verification', icon: Blocks },
]

const activityData = [
  { day: 'Mon', scans: 35 }, { day: 'Tue', scans: 52 },
  { day: 'Wed', scans: 42 }, { day: 'Thu', scans: 76 },
  { day: 'Fri', scans: 58 }, { day: 'Sat', scans: 91 },
  { day: 'Sun', scans: 68 },
]

const initialReports = [
  { target: 'paypal-secure-login.com', type: 'URL Scan', risk: 92, status: 'Malicious', date: 'Just now' },
  { target: 'amazon.in', type: 'URL Scan', risk: 8, status: 'Safe', date: '12 min ago' },
  { target: 'Urgent account verification', type: 'Message', risk: 78, status: 'Suspicious', date: '35 min ago' },
  { target: 'github.com', type: 'URL Scan', risk: 4, status: 'Safe', date: '1 hour ago' },
]

async function createAnalysis(payload) {
  const response = await fetch(`${API_BASE}/api/v1/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...payload,
      include_threat_intel: false,
      register_on_chain: false,
    }),
  })

  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.detail || 'Backend analysis failed.')
  }

  return data
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
    localStorage.setItem('trustguard_reports', JSON.stringify(reports))
  }, [reports])

  const notify = (text) => {
    setToast(text)
    setTimeout(() => setToast(''), 2600)
  }

  const runUrlScan = async () => {
    if (!url.trim()) return notify('Please enter a URL first.')

    setScanning(true)
    setUrlResult(null)

    try {
      const report = await createAnalysis({ url: url.trim() })

      const rawUrlResult = report.findings?.url_tls?.raw || {}

      const findings = rawUrlResult.findings?.map((finding) =>
        finding.evidence || finding.indicator
      ) || ['No security findings were returned.']

      const result = {
        risk: report.risk_score ?? 0,
        status: report.risk_category || 'Inconclusive',
        findings,
      }

      setUrlResult(result)

      setReports((previous) => [
        {
          target: url.trim(),
          type: 'URL Scan',
          risk: result.risk,
          status: result.status,
          date: 'Just now',
        },
        ...previous,
      ])
    } catch (error) {
      notify(error.message || 'Could not reach the backend.')
    } finally {
      setScanning(false)
    }
  }

  const runMessageScan = async () => {
    if (!message.trim()) return notify('Paste a message to analyze.')

    setScanning(true)
    setMessageResult(null)

    try {
      const report = await createAnalysis({ message: message.trim() })

      const rawMessageResult =
        report.findings?.ai_analysis?.raw || {}

      if (rawMessageResult.status === 'error') {
        throw new Error(
          rawMessageResult.error || 'Gemini analysis failed.'
        )
      }

      const analysis = rawMessageResult.message_analysis || {}

      const indicators = (analysis.scam_indicators || []).map(
        (item) => item.evidence || item.indicator
      )

      const result = {
        risk: report.risk_score ?? 0,
        status:
          report.risk_category ||
          analysis.classification ||
          'Inconclusive',
        indicators,
      }

      setMessageResult(result)

      setReports((previous) => [
        {
          target: `${message.slice(0, 42)}${message.length > 42 ? '…' : ''}`,
          type: 'Message',
          risk: result.risk,
          status: result.status,
          date: 'Just now',
        },
        ...previous,
      ])
    } catch (error) {
      notify(error.message || 'Could not reach the backend.')
    } finally {
      setScanning(false)
    }
  }

  const menuClick = (name) => {
    setPage(name)
    setMobileOpen(false)
  }

  const StatCard = ({ title, value, change, icon: Icon, color }) => (
    <div className="stat-card">
      <div className="stat-top">
        <span>{title}</span>
        <span className={`stat-icon ${color}`}>
          <Icon size={19} />
        </span>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-change">
        <ArrowUpRight size={14} /> {change}
      </div>
    </div>
  )

  const RiskBadge = ({ status }) => {
    const statusText = String(status || 'Inconclusive').toLowerCase()

    const cls =
      statusText.includes('safe') || statusText.includes('low')
        ? 'safe'
        : statusText.includes('malicious') || statusText.includes('scam')
          ? 'danger'
          : 'warning'

    return <span className={`risk-badge ${cls}`}>{status}</span>
  }

  const PageHeader = ({ title, subtitle }) => (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      <span className="live-indicator">
        <i /> SYSTEM OPERATIONAL
      </span>
    </div>
  )

  const Dashboard = () => (
    <>
      <PageHeader
        title="Security Overview"
        subtitle="Monitor threats, investigations and your digital trust environment."
      />

      <div className="stats-grid">
        <StatCard
          title="Total Investigations"
          value={reports.length + 1248}
          change="+12.8% this week"
          icon={ScanSearch}
          color="blue"
        />
        <StatCard
          title="Threats Detected"
          value="186"
          change="+8.2% this week"
          icon={ShieldAlert}
          color="red"
        />
        <StatCard
          title="Safe Websites"
          value="1,062"
          change="+5.4% this week"
          icon={ShieldCheck}
          color="green"
        />
        <StatCard
          title="Reports Verified"
          value="98.6%"
          change="Blockchain integrity"
          icon={Blocks}
          color="purple"
        />
      </div>

      <div className="dashboard-grid">
        <section className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h3>Investigation Activity</h3>
              <p>Security scans over the last 7 days</p>
            </div>
            <span className="period-pill">Last 7 days</span>
          </div>

          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData}>
                <defs>
                  <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6687ff" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#6687ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#242b3a" vertical={false} />
                <XAxis dataKey="day" stroke="#737e94" tickLine={false} axisLine={false} />
                <YAxis stroke="#737e94" tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#151c2b', border: '1px solid #303b51', borderRadius: 10 }} />
                <Area
                  type="monotone"
                  dataKey="scans"
                  stroke="#7893ff"
                  strokeWidth={2.5}
                  fill="url(#scanGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel distribution-panel">
          <div className="panel-heading">
            <div>
              <h3>Threat Distribution</h3>
              <p>Current scan classification</p>
            </div>
          </div>

          <div className="donut-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={[
                    { name: 'Safe', value: 68 },
                    { name: 'Suspicious', value: 22 },
                    { name: 'Malicious', value: 10 },
                  ]}
                  innerRadius={57}
                  outerRadius={82}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {['#31c48d', '#f6ad55', '#f06475'].map((color, index) => (
                    <Cell key={index} fill={color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>

            <div className="donut-center">
              <strong>100%</strong>
              <span>Analyzed</span>
            </div>
          </div>

          <div className="legend">
            <span><i className="green-dot" /> Safe <b>68%</b></span>
            <span><i className="yellow-dot" /> Suspicious <b>22%</b></span>
            <span><i className="red-dot" /> Malicious <b>10%</b></span>
          </div>
        </section>
      </div>

      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h3>Recent Investigations</h3>
            <p>Latest security analysis activity</p>
          </div>
          <button className="text-button" onClick={() => setPage('Scan History')}>
            View all <ChevronRight size={15} />
          </button>
        </div>

        <ReportTable reports={reports.slice(0, 5)} RiskBadge={RiskBadge} />
      </section>

      <div className="quick-actions">
        <button onClick={() => setPage('URL Scanner')}>
          <Globe size={18} /> Scan a URL <ArrowUpRight size={15} />
        </button>
        <button onClick={() => setPage('Message Analyzer')}>
          <MessageSquareWarning size={18} /> Analyze a message <ArrowUpRight size={15} />
        </button>
        <button onClick={() => setPage('Blockchain Verification')}>
          <Blocks size={18} /> Verify a report <ArrowUpRight size={15} />
        </button>
      </div>
    </>
  )

  const ReportTable = ({ reports: rows, RiskBadge: Badge }) => (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Target / Indicator</th>
            <th>Investigation</th>
            <th>Risk score</th>
            <th>Classification</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((report, index) => (
            <tr key={index}>
              <td className="target-cell">{report.target}</td>
              <td>{report.type}</td>
              <td><strong>{report.risk}/100</strong></td>
              <td><Badge status={report.status} /></td>
              <td className="muted-cell">{report.date}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  const URLScanner = () => (
    <>
      <PageHeader
        title="URL Security Scanner"
        subtitle="Inspect suspicious links, domains, DNS records and TLS security."
      />

      <section className="panel scanner-panel">
        <div className="scanner-icon">
          <Globe size={25} />
        </div>

        <h2>Analyze a website URL</h2>
        <p>Enter a website address to start a live security investigation.</p>

        <div className="url-input-row">
          <input
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onKeyDown={(event) => event.key === 'Enter' && runUrlScan()}
            placeholder="https://example.com"
          />

          <button className="primary-button" onClick={runUrlScan} disabled={scanning}>
            {scanning
              ? <RefreshCw className="spin" size={17} />
              : <ScanSearch size={17} />}
            {scanning ? 'Analyzing…' : 'Analyze URL'}
          </button>
        </div>

        <div className="input-hint">
          <Lock size={13} /> Live backend analysis · DNS, TLS and redirect inspection
        </div>
      </section>

      {urlResult && (
        <section className="panel result-panel">
          <div className="result-header">
            <div>
              <span className="eyebrow">LIVE SCAN RESULT</span>
              <h2>{url}</h2>
            </div>
            <RiskBadge status={urlResult.status} />
          </div>

          <div className="risk-score">
            <div>
              <span>Risk score</span>
              <strong>{urlResult.risk}<small>/100</small></strong>
            </div>
            <div className="risk-meter">
              <i style={{ width: `${urlResult.risk}%` }} />
            </div>
          </div>

          <h3>Security findings</h3>

          {urlResult.findings.map((finding, index) => (
            <div className="finding" key={index}>
              <AlertTriangle size={17} /> {finding}
            </div>
          ))}
        </section>
      )}
    </>
  )

  const MessageAnalyzer = () => (
    <>
      <PageHeader
        title="AI Message Analyzer"
        subtitle="Identify phishing, scam messages and social engineering attempts."
      />

      <section className="panel scanner-panel">
        <div className="scanner-icon purple-bg">
          <MessageSquareWarning size={25} />
        </div>

        <h2>Analyze a suspicious message</h2>
        <p>Paste an email, SMS or chat message for a live AI security assessment.</p>

        <textarea
          className="message-input"
          value={message}
          onChange={(event) => setMessage(event.target.value)}
          placeholder="Paste the suspicious message here…"
        />

        <div className="message-actions">
          <span className="input-hint">
            Do not include real passwords or OTPs.
          </span>

          <button className="primary-button" onClick={runMessageScan} disabled={scanning}>
            {scanning ? 'Analyzing…' : 'Analyze Message'}
            <Zap size={16} />
          </button>
        </div>
      </section>

      {messageResult && (
        <section className="panel result-panel">
          <div className="result-header">
            <div>
              <span className="eyebrow">AI ANALYSIS RESULT</span>
              <h2>{messageResult.status}</h2>
            </div>
            <RiskBadge status={messageResult.status} />
          </div>

          <div className="risk-score">
            <div>
              <span>Risk score</span>
              <strong>{messageResult.risk}<small>/100</small></strong>
            </div>
            <div className="risk-meter">
              <i style={{ width: `${messageResult.risk}%` }} />
            </div>
          </div>

          <h3>Detected indicators</h3>

          {messageResult.indicators.length ? (
            messageResult.indicators.map((indicator, index) => (
              <div className="finding" key={index}>
                <AlertTriangle size={17} /> {indicator}
              </div>
            ))
          ) : (
            <div className="finding">
              <CheckCircle2 size={17} /> No scam indicators detected.
            </div>
          )}
        </section>
      )}
    </>
  )

  const HistoryPage = () => (
    <>
      <PageHeader
        title="Investigation History"
        subtitle="Review previous URL and message investigations."
      />

      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h3>All investigations</h3>
            <p>{reports.length} records in this demo session</p>
          </div>
        </div>

        <ReportTable reports={reports} RiskBadge={RiskBadge} />
      </section>
    </>
  )

  const ReportsPage = () => (
    <>
      <PageHeader
        title="Investigation Reports"
        subtitle="Review findings, evidence and security recommendations."
      />

      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h3>Available reports</h3>
            <p>Reports are created by the connected TrustGuard backend.</p>
          </div>
        </div>

        <ReportTable reports={reports} RiskBadge={RiskBadge} />

        <div className="report-note">
          <ShieldCheck size={17} />
          Each live scan creates a backend report with an integrity hash.
        </div>
      </section>
    </>
  )

  const ThreatPage = () => (
    <>
      <PageHeader
        title="Threat Intelligence"
        subtitle="Threat indicators and intelligence-source monitoring."
      />

      <div className="stats-grid">
        <StatCard title="Known indicators" value="2,481" change="Demo data" icon={ShieldAlert} color="red" />
        <StatCard title="Threat sources" value="08" change="Optional API keys required" icon={Activity} color="blue" />
        <StatCard title="Domains flagged" value="186" change="Demo data" icon={Globe} color="purple" />
      </div>

      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h3>Threat intelligence feeds</h3>
            <p>URLhaus and VirusTotal run when their API credentials are available.</p>
          </div>
        </div>

        {[
          'Malicious domain reputation',
          'URL threat database',
          'Phishing intelligence feed',
          'Website security indicators',
        ].map((item, index) => (
          <div className="feed-row" key={index}>
            <ShieldAlert size={18} />
            <span>{item}</span>
            <RiskBadge status="Optional integration" />
          </div>
        ))}
      </section>
    </>
  )

  const BlockchainPage = () => (
    <>
      <PageHeader
        title="Blockchain Verification"
        subtitle="Verify report integrity using on-chain report hashes."
      />

      <section className="panel scanner-panel">
        <div className="scanner-icon purple-bg">
          <Blocks size={25} />
        </div>

        <h2>Verify an investigation report</h2>
        <p>Enter a report hash to check its integrity against the blockchain record.</p>

        <div className="url-input-row">
          <input
            value={hash}
            onChange={(event) => setHash(event.target.value)}
            placeholder="Enter report hash (SHA-256)"
          />

          <button
            className="primary-button"
            onClick={() => {
              setVerified(hash.trim() ? 'pending' : 'empty')
              notify(
                hash.trim()
                  ? 'Blockchain credentials are required for on-chain verification.'
                  : 'Enter a report hash.'
              )
            }}
          >
            Verify hash <ShieldCheck size={17} />
          </button>
        </div>

        {verified === 'pending' && (
          <div className="report-note">
            <Activity size={17} />
            On-chain verification becomes available when Sepolia credentials are configured.
          </div>
        )}
      </section>

      <div className="stats-grid">
        <StatCard title="Network" value="Sepolia" change="Test network" icon={Blocks} color="purple" />
        <StatCard title="Contract status" value="Optional" change="Requires teammate credentials" icon={Lock} color="blue" />
        <StatCard title="Integrity checks" value="Ready" change="Local report hashes enabled" icon={CheckCircle2} color="green" />
      </div>
    </>
  )

  const currentPage = () => {
  switch (page) {
    case 'URL Scanner':
      return URLScanner()
    case 'Message Analyzer':
      return MessageAnalyzer()
    case 'Investigation Reports':
      return ReportsPage()
    case 'Threat Intelligence':
      return ThreatPage()
    case 'Scan History':
      return HistoryPage()
    case 'Blockchain Verification':
      return BlockchainPage()
    default:
      return Dashboard()
  }
}

  return (
    <div className="app-shell">
      {mobileOpen && (
        <div className="mobile-overlay" onClick={() => setMobileOpen(false)} />
      )}

      <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={23} />
          </div>
          <div>
            <strong>TrustGuard<span>AI</span></strong>
            <small>DIGITAL TRUST INTELLIGENCE</small>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <nav>
          {navItems.map((item) => (
            <button
              key={item.name}
              className={`nav-item ${page === item.name ? 'active' : ''}`}
              onClick={() => menuClick(item.name)}
            >
              <item.icon size={18} />
              <span>{item.name}</span>
              {page === item.name && <i />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-card">
            <span className="system-dot" />
            <div>
              <b>Protection active</b>
              <small>Live backend connected</small>
            </div>
          </div>

          <button className="nav-item" onClick={() => notify('Settings will be available soon.')}>
            <Settings size={18} /> Settings
          </button>

          <div className="profile">
            <div className="avatar">TG</div>
            <div>
              <b>Security Analyst</b>
              <small>Investigation workspace</small>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setMobileOpen(!mobileOpen)}>
            <Menu />
          </button>

          <div className="breadcrumb">
            Workspace <ChevronRight size={14} /> <b>{page}</b>
          </div>

          <div className="top-actions">
            <div className="environment"><i /> LIVE BACKEND</div>

            <button className="icon-button" onClick={() => notify('You are all caught up.')}>
              <Bell size={18} />
              <i />
            </button>

            <div className="top-avatar">TG</div>
          </div>
        </header>

        <div className="page-content">
          {currentPage()}

          <footer>
            TRUSTGUARD AI <span>·</span> Digital Trust Intelligence <span>·</span> Live investigation workspace
          </footer>
        </div>
      </main>

      {toast && (
        <div className="toast">
          <CheckCircle2 size={17} /> {toast}
        </div>
      )}
    </div>
  )
}

export default App