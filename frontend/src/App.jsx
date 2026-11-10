
import { useEffect, useState } from 'react'
import {
  ShieldCheck, LayoutDashboard, Globe, MessageSquareWarning,
  FileSearch, ShieldAlert, History, Blocks, Settings, Bell,
  Search, Menu, ArrowUpRight, ArrowDownRight, Activity,
  Lock, ExternalLink, AlertTriangle, CheckCircle2, XCircle,
  ScanSearch, Zap, Copy, ChevronRight, RefreshCw
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  Tooltip, CartesianGrid, PieChart, Pie, Cell
} from 'recharts'
import './App.css'

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

  const runUrlScan = () => {
    if (!url.trim()) return notify('Please enter a URL first.')
    setScanning(true)
    setUrlResult(null)
    setTimeout(() => {
      const suspicious = /login|verify|secure|update|free|paypa1|amaz0n/i.test(url)
      const result = {
        risk: suspicious ? 86 : 12,
        status: suspicious ? 'Suspicious' : 'Low Risk',
        findings: suspicious
          ? ['Suspicious keywords detected in URL', 'Potential impersonation indicators', 'Further threat-intelligence verification required']
          : ['URL format validated', 'No obvious heuristic warning detected', 'Live DNS and TLS verification requires backend connection'],
      }
      setUrlResult(result)
      setReports(prev => [{ target: url, type: 'URL Scan', risk: result.risk, status: result.status, date: 'Just now' }, ...prev])
      setScanning(false)
    }, 1100)
  }

  const runMessageScan = () => {
    if (!message.trim()) return notify('Paste a message to analyze.')
    setScanning(true)
    setMessageResult(null)
    setTimeout(() => {
      const suspicious = /urgent|password|verify|bank|otp|click|account|prize|suspended/i.test(message)
      const result = {
        risk: suspicious ? 82 : 15,
        status: suspicious ? 'Potential Scam' : 'No obvious scam indicators',
        indicators: [
          ...( /urgent|immediately|now/i.test(message) ? ['Urgency or pressure tactics'] : []),
          ...( /password|otp|bank|account/i.test(message) ? ['Sensitive account information requested or mentioned'] : []),
          ...( /https?:\/\//i.test(message) ? ['URL found in message'] : []),
        ]
      }
      setMessageResult(result)
      setReports(prev => [{ target: message.slice(0, 42) + (message.length > 42 ? '…' : ''), type: 'Message', risk: result.risk, status: result.status, date: 'Just now' }, ...prev])
      setScanning(false)
    }, 1100)
  }

  const menuClick = (name) => {
    setPage(name)
    setMobileOpen(false)
  }

  const StatCard = ({ title, value, change, icon: Icon, color }) => (
    <div className="stat-card">
      <div className="stat-top">
        <span>{title}</span>
        <span className={`stat-icon ${color}`}><Icon size={19}/></span>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-change"><ArrowUpRight size={14}/> {change}</div>
    </div>
  )

  const RiskBadge = ({ status }) => {
    const cls = status.toLowerCase().includes('safe') || status.toLowerCase().includes('low') ? 'safe'
      : status.toLowerCase().includes('malicious') || status.toLowerCase().includes('scam') ? 'danger' : 'warning'
    return <span className={`risk-badge ${cls}`}>{status}</span>
  }

  const PageHeader = ({ title, subtitle }) => (
    <div className="page-heading">
      <div><h1>{title}</h1><p>{subtitle}</p></div>
      <span className="live-indicator"><i/> SYSTEM OPERATIONAL</span>
    </div>
  )

  const Dashboard = () => (
    <>
      <PageHeader title="Security Overview" subtitle="Monitor threats, investigations and your digital trust environment."/>
      <div className="stats-grid">
        <StatCard title="Total Investigations" value={reports.length + 1248} change="+12.8% this week" icon={ScanSearch} color="blue"/>
        <StatCard title="Threats Detected" value="186" change="+8.2% this week" icon={ShieldAlert} color="red"/>
        <StatCard title="Safe Websites" value="1,062" change="+5.4% this week" icon={ShieldCheck} color="green"/>
        <StatCard title="Reports Verified" value="98.6%" change="Blockchain integrity" icon={Blocks} color="purple"/>
      </div>
      <div className="dashboard-grid">
        <section className="panel chart-panel">
          <div className="panel-heading"><div><h3>Investigation Activity</h3><p>Security scans over the last 7 days</p></div><span className="period-pill">Last 7 days</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData}>
                <defs><linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#6687ff" stopOpacity={0.35}/><stop offset="100%" stopColor="#6687ff" stopOpacity={0}/></linearGradient></defs>
                <CartesianGrid stroke="#242b3a" vertical={false}/>
                <XAxis dataKey="day" stroke="#737e94" tickLine={false} axisLine={false}/>
                <YAxis stroke="#737e94" tickLine={false} axisLine={false}/>
                <Tooltip contentStyle={{background:'#151c2b',border:'1px solid #303b51',borderRadius:10}}/>
                <Area type="monotone" dataKey="scans" stroke="#7893ff" strokeWidth={2.5} fill="url(#scanGradient)"/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>
        <section className="panel distribution-panel">
          <div className="panel-heading"><div><h3>Threat Distribution</h3><p>Current scan classification</p></div></div>
          <div className="donut-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart><Pie data={[{name:'Safe',value:68},{name:'Suspicious',value:22},{name:'Malicious',value:10}]} innerRadius={57} outerRadius={82} paddingAngle={4} dataKey="value" stroke="none">
                {[ '#31c48d','#f6ad55','#f06475' ].map((c,i)=><Cell key={i} fill={c}/>)}
              </Pie><Tooltip/></PieChart>
            </ResponsiveContainer>
            <div className="donut-center"><strong>100%</strong><span>Analyzed</span></div>
          </div>
          <div className="legend">
            <span><i className="green-dot"/> Safe <b>68%</b></span>
            <span><i className="yellow-dot"/> Suspicious <b>22%</b></span>
            <span><i className="red-dot"/> Malicious <b>10%</b></span>
          </div>
        </section>
      </div>
      <section className="panel table-panel">
        <div className="panel-heading"><div><h3>Recent Investigations</h3><p>Latest security analysis activity</p></div><button className="text-button" onClick={()=>setPage('Scan History')}>View all <ChevronRight size={15}/></button></div>
        <ReportTable reports={reports.slice(0,5)} RiskBadge={RiskBadge}/>
      </section>
      <div className="quick-actions">
        <button onClick={()=>setPage('URL Scanner')}><Globe size={18}/> Scan a URL <ArrowUpRight size={15}/></button>
        <button onClick={()=>setPage('Message Analyzer')}><MessageSquareWarning size={18}/> Analyze a message <ArrowUpRight size={15}/></button>
        <button onClick={()=>setPage('Blockchain Verification')}><Blocks size={18}/> Verify a report <ArrowUpRight size={15}/></button>
      </div>
    </>
  )

  const ReportTable = ({ reports: rows, RiskBadge: Badge }) => (
    <div className="table-scroll"><table><thead><tr><th>Target / Indicator</th><th>Investigation</th><th>Risk score</th><th>Classification</th><th>Time</th></tr></thead>
      <tbody>{rows.map((r,i)=><tr key={i}><td className="target-cell">{r.target}</td><td>{r.type}</td><td><strong>{r.risk}/100</strong></td><td><Badge status={r.status}/></td><td className="muted-cell">{r.date}</td></tr>)}</tbody>
    </table></div>
  )

  const URLScanner = () => (
    <>
      <PageHeader title="URL Security Scanner" subtitle="Inspect suspicious links, domains, DNS records and TLS security."/>
      <section className="panel scanner-panel">
        <div className="scanner-icon"><Globe size={25}/></div>
        <h2>Analyze a website URL</h2><p>Enter a website address to start a security investigation.</p>
        <div className="url-input-row"><input value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==='Enter'&&runUrlScan()} placeholder="https://example.com"/><button className="primary-button" onClick={runUrlScan} disabled={scanning}>{scanning?<RefreshCw className="spin" size={17}/>:<ScanSearch size={17}/>} {scanning?'Analyzing…':'Analyze URL'}</button></div>
        <div className="input-hint"><Lock size={13}/> Analysis preview · Connect backend for live DNS, TLS and threat intelligence</div>
      </section>
      {urlResult && <section className="panel result-panel">
        <div className="result-header"><div><span className="eyebrow">SCAN RESULT</span><h2>{url}</h2></div><RiskBadge status={urlResult.status}/></div>
        <div className="risk-score"><div><span>Risk score</span><strong>{urlResult.risk}<small>/100</small></strong></div><div className="risk-meter"><i style={{width:`${urlResult.risk}%`}}/></div></div>
        <h3>Security findings</h3>{urlResult.findings.map((f,i)=><div className="finding" key={i}><AlertTriangle size={17}/>{f}</div>)}
      </section>}
    </>
  )

  const MessageAnalyzer = () => (
    <>
      <PageHeader title="AI Message Analyzer" subtitle="Identify phishing, scam messages and social engineering attempts."/>
      <section className="panel scanner-panel">
        <div className="scanner-icon purple-bg"><MessageSquareWarning size={25}/></div>
        <h2>Analyze a suspicious message</h2><p>Paste an email, SMS or chat message for a security assessment.</p>
        <textarea className="message-input" value={message} onChange={e=>setMessage(e.target.value)} placeholder="Paste the suspicious message here…"/>
        <div className="message-actions"><span className="input-hint">Do not include real passwords or OTPs.</span><button className="primary-button" onClick={runMessageScan} disabled={scanning}>{scanning?'Analyzing…':'Analyze Message'} <Zap size={16}/></button></div>
      </section>
      {messageResult && <section className="panel result-panel"><div className="result-header"><div><span className="eyebrow">AI ANALYSIS PREVIEW</span><h2>{messageResult.status}</h2></div><RiskBadge status={messageResult.status}/></div><div className="risk-score"><div><span>Risk score</span><strong>{messageResult.risk}<small>/100</small></strong></div><div className="risk-meter"><i style={{width:`${messageResult.risk}%`}}/></div></div><h3>Detected indicators</h3>{messageResult.indicators.length?messageResult.indicators.map((x,i)=><div className="finding" key={i}><AlertTriangle size={17}/>{x}</div>):<div className="finding"><CheckCircle2 size={17}/>No obvious keyword indicators detected.</div>}</section>}
    </>
  )

  const HistoryPage = () => <><PageHeader title="Investigation History" subtitle="Review previous URL and message investigations."/><section className="panel table-panel"><div className="panel-heading"><div><h3>All investigations</h3><p>{reports.length} records in this demo session</p></div></div><ReportTable reports={reports} RiskBadge={RiskBadge}/></section></>

  const ReportsPage = () => <><PageHeader title="Investigation Reports" subtitle="Review findings, evidence and security recommendations."/><section className="panel table-panel"><div className="panel-heading"><div><h3>Available reports</h3><p>Select a report from your investigation history.</p></div></div><ReportTable reports={reports} RiskBadge={RiskBadge}/><div className="report-note"><ShieldCheck size={17}/> Reports are demo previews. Final evidence and signed reports will come from the central backend.</div></section></>

  const ThreatPage = () => <><PageHeader title="Threat Intelligence" subtitle="Threat indicators and intelligence-source monitoring."/><div className="stats-grid"><StatCard title="Known indicators" value="2,481" change="Demo data" icon={ShieldAlert} color="red"/><StatCard title="Threat sources" value="08" change="Integration pending" icon={Activity} color="blue"/><StatCard title="Domains flagged" value="186" change="Demo data" icon={Globe} color="purple"/></div><section className="panel table-panel"><div className="panel-heading"><div><h3>Threat intelligence feeds</h3><p>External source integration status</p></div></div>{['Malicious domain reputation','URL threat database','Phishing intelligence feed','Website security indicators'].map((x,i)=><div className="feed-row" key={i}><ShieldAlert size={18}/><span>{x}</span><RiskBadge status="Awaiting API integration"/></div>)}</section></>

  const BlockchainPage = () => {
    return <><PageHeader title="Blockchain Verification" subtitle="Verify report integrity using on-chain report hashes."/><section className="panel scanner-panel"><div className="scanner-icon purple-bg"><Blocks size={25}/></div><h2>Verify an investigation report</h2><p>Enter a report hash to check its integrity against the blockchain record.</p><div className="url-input-row"><input value={hash} onChange={e=>setHash(e.target.value)} placeholder="Enter report hash (SHA-256)"/><button className="primary-button" onClick={()=>{setVerified(hash.trim()? 'pending':'empty');notify(hash.trim()?'Verification interface ready.':'Enter a report hash.')}}>Verify hash <ShieldCheck size={17}/></button></div>{verified==='pending'&&<div className="report-note"><Activity size={17}/> Blockchain verification will be available when the Sepolia contract API is connected.</div>}</section><div className="stats-grid"><StatCard title="Network" value="Sepolia" change="Test network" icon={Blocks} color="purple"/><StatCard title="Contract status" value="Pending" change="Team integration" icon={Lock} color="blue"/><StatCard title="Integrity checks" value="Ready UI" change="API connection pending" icon={CheckCircle2} color="green"/></div></>
  }

  const currentPage = () => {
    switch(page) {
      case 'URL Scanner': return <URLScanner/>
      case 'Message Analyzer': return <MessageAnalyzer/>
      case 'Investigation Reports': return <ReportsPage/>
      case 'Threat Intelligence': return <ThreatPage/>
      case 'Scan History': return <HistoryPage/>
      case 'Blockchain Verification': return <BlockchainPage/>
      default: return <Dashboard/>
    }
  }

  return (
    <div className="app-shell">
      {mobileOpen && <div className="mobile-overlay" onClick={()=>setMobileOpen(false)}/>}
      <aside className={`sidebar ${mobileOpen?'sidebar-open':''}`}>
        <div className="brand"><div className="brand-mark"><ShieldCheck size={23}/></div><div><strong>TrustGuard<span>AI</span></strong><small>DIGITAL TRUST INTELLIGENCE</small></div></div>
        <div className="nav-label">WORKSPACE</div>
        <nav>{navItems.map(item=><button key={item.name} className={`nav-item ${page===item.name?'active':''}`} onClick={()=>menuClick(item.name)}><item.icon size={18}/><span>{item.name}</span>{page===item.name&&<i/>}</button>)}</nav>
        <div className="sidebar-bottom"><div className="system-card"><span className="system-dot"/><div><b>Protection active</b><small>Demo environment</small></div></div><button className="nav-item" onClick={()=>notify('Settings will be available soon.')}><Settings size={18}/> Settings</button><div className="profile"><div className="avatar">TG</div><div><b>Security Analyst</b><small>Investigation workspace</small></div></div></div>
      </aside>
      <main className="main-area">
        <header className="topbar"><button className="mobile-menu" onClick={()=>setMobileOpen(!mobileOpen)}><Menu/></button><div className="breadcrumb">Workspace <ChevronRight size={14}/> <b>{page}</b></div><div className="top-actions"><div className="environment"><i/> DEMO MODE</div><button className="icon-button" onClick={()=>notify('You are all caught up.')}><Bell size={18}/><i/></button><div className="top-avatar">TG</div></div></header>
        <div className="page-content">{currentPage()}<footer>TRUSTGUARD AI <span>·</span> Digital Trust Intelligence <span>·</span> Demo environment</footer></div>
      </main>
      {toast&&<div className="toast"><CheckCircle2 size={17}/>{toast}</div>}
    </div>
  )
}

export default App
