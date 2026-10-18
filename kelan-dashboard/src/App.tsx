import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Terminal, BookOpen, Key, Cpu, HardDrive, Cpu as Memory, 
  Search, Play, Download, RefreshCw, AlertTriangle, CheckCircle, 
  ChevronLeft, ChevronRight, Activity, Globe, Code, Network, 
  ExternalLink, FileCode, Check, Server
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';

// Severity details with glowing colors
const SEVERITIES = {
  CRITICAL: { name: 'CRITICAL', color: '#f85149', glow: 'shadow-[0_0_15px_rgba(248,81,73,0.3)]', text: 'text-red-500' },
  HIGH: { name: 'HIGH', color: '#d29922', glow: 'shadow-[0_0_15px_rgba(210,153,34,0.3)]', text: 'text-yellow-500' },
  MEDIUM: { name: 'MEDIUM', color: '#58a6ff', glow: 'shadow-[0_0_15px_rgba(88,166,255,0.3)]', text: 'text-blue-500' },
  LOW: { name: 'LOW', color: '#8b949e', glow: 'shadow-[0_0_15px_rgba(139,148,158,0.3)]', text: 'text-slate-400' },
  SAFE: { name: 'SAFE', color: '#3fb950', glow: 'shadow-[0_0_15px_rgba(63,185,80,0.3)]', text: 'text-emerald-500' }
};

const SEV_COLORS = ['#f85149', '#d29922', '#58a6ff', '#8b949e'];

// Documentation sections verbatim
const DOCS_SECTIONS = [
  {
    id: 'overview',
    title: '1. Overview',
    content: (
      <div>
        <p className="text-slate-300 mb-4 leading-relaxed">
          <strong>Kelan</strong> is an AI-native, zero-telemetry security platform. It is built around one idea: <em>detection is deterministic, and the AI is advisory</em>. Code never leaves the machine — a local LLM (via Ollama) is used only to phrase findings, never to invent them.
        </p>
        <p className="text-slate-300 mb-4">The platform ships four families of capability:</p>
        <div className="overflow-x-auto mb-6">
          <table className="min-w-full divide-y divide-slate-800 text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-2 pr-4 font-semibold">Family</th>
                <th className="py-2 px-4 font-semibold">What it does</th>
                <th className="py-2 pl-4 font-semibold">Location</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              <tr>
                <td className="py-3 pr-4 font-semibold text-blue-400">Scanning engine</td>
                <td className="py-3 px-4">SAST (AST-aware static analysis), DAST (dynamic web testing), SCA (dependency vulnerabilities), recon (ports), cloud/API-leak audit, runtime analysis (ReDoS, zip bombs), attack-chain correlation</td>
                <td className="py-3 pl-4 font-mono text-xs">kelan/scanner/, kelan/dast/, kelan/plugins/, kelan/analyze/</td>
              </tr>
              <tr>
                <td className="py-3 pr-4 font-semibold text-blue-400">Trust engine</td>
                <td className="py-3 px-4">Hybrid LLM + deterministic fallback scoring of connection metrics, with a circuit breaker and Prometheus telemetry</td>
                <td className="py-3 pl-4 font-mono text-xs">kelan/ai/</td>
              </tr>
              <tr>
                <td className="py-3 pr-4 font-semibold text-blue-400">eBPF kernel shield</td>
                <td className="py-3 px-4">XDP packet filter (UDP 9999/AITP v4), per-CPU rate limiting, wire-speed IP blacklisting</td>
                <td className="py-3 pl-4 font-mono text-xs">kelan-ebpf/</td>
              </tr>
              <tr>
                <td className="py-3 pr-4 font-semibold text-blue-400">PQC key exchange</td>
                <td className="py-3 px-4">ML-KEM-768 (Kyber768) handshake + key derivation</td>
                <td className="py-3 pl-4 font-mono text-xs">kelan/protocol/</td>
              </tr>
            </tbody>
          </table>
        </div>
        <h4 className="text-md font-semibold text-slate-200 mb-2">1.1 End Goal</h4>
        <p className="text-slate-300 mb-4">
          A user installs the repo, connects their local LLM, and runs a single command against a <em>local codebase</em>, a <em>git repository</em>, or a <em>URL</em>. Kelan then takes its time and reports:
        </p>
        <ul className="list-disc list-inside text-slate-300 space-y-1 mb-4">
          <li>Broken endpoints &amp; open ports</li>
          <li>OWASP Top 10 gaps (A01–A10 coverage)</li>
          <li>Attack chains (correlated evidence across engines)</li>
          <li>Cloud misconfigurations &amp; API leaks (provider-tied credentials)</li>
          <li>Runtime chokes (ReDoS, resource exhaustion, zip bombs)</li>
          <li>Thread-hijacking / data-race surface</li>
          <li>Token-bucket / rate-limit bypasses (static + live proof)</li>
        </ul>
        <p className="text-slate-300">
          Output is <strong>installable, reportable, and defensible</strong>: JSON, SARIF 2.1.0, HTML, terminal, and a CI gate with exit codes.
        </p>
      </div>
    )
  },
  {
    id: 'architecture',
    title: '2. Architecture',
    content: (
      <div>
        <pre className="bg-slate-900 border border-slate-800 p-4 rounded-lg font-mono text-xs text-blue-400 overflow-x-auto mb-6">
{`                    ┌──────────────────────────────────────────────┐
                    │               kelan CLI (cli/main.py)        │
                    │   interactive menu  ·  subcommand routing    │
                    └────────────────────┬─────────────────────────┘
                                         │ delegates
                    ┌────────────────────▼─────────────────────────┐
                    │        kelan.run — Scheduler entrypoint     │
                    │  target parse → plugin topo order → execute │
                    └──────┬──────────┬──────────┬───────────┬────┘
                           │          │          │           │
              ┌────────────▼──┐ ┌─────▼──────┐ ┌─▼──────────┐ ┌▼───────────┐
              │  core/plugin  │ │ core/      │ │ plugins/   │ │ engines    │
              │  Registry     │ │ finding.py │ │ sca, ports,│ │ scanner,   │
              │  Scheduler    │ │ evidence   │ │ dast/sast  │ │ dast,      │
              │  ScanContext  │ │ schema     │ │ adapters   │ │ analyze,   │
              └───────────────┘ └────────────┘ └────────────┘ │ recon,     │
                                                              │ cloud,     │
                                                              │ chains     │
                                                              └────────────┘`}
        </pre>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-800 text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-2 pr-4 font-semibold">Module</th>
                <th className="py-2 pl-4 font-semibold">Responsibility</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              <tr>
                <td className="py-2 pr-4 font-mono text-xs text-blue-400">kelan/cli/main.py</td>
                <td className="py-2 pl-4">Top-level dispatcher: interactive menu, subcommand routing (run/sast/dast/recon/git). All scanning delegates to kelan.run:main.</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs text-blue-400">kelan/run.py</td>
                <td className="py-2 pl-4">Single source of truth for scheduler execution. Flags: --only/--skip/--config/--json/--sarif/--ci-gate/--show.</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs text-blue-400">kelan/core/finding.py</td>
                <td className="py-2 pl-4">Unified evidence schema: Severity (CRITICAL→INFO), Confidence (none/weak/medium/strong), Evidence, Finding, FindingSet.</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs text-blue-400">kelan/core/plugin.py</td>
                <td className="py-2 pl-4">Plugin framework: ScopeKind, ScanTarget, ScanConfig, ScanContext, ScanPlugin, PluginRegistry, topological Scheduler.</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs text-blue-400">kelan/plugins/</td>
                <td className="py-2 pl-4">Auto-registered plugins: sca.py, ports.py, dast_adapter.py, sast_adapter.py, plus runtime.py, cloud.py, chains.py.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    )
  },
  {
    id: 'install',
    title: '3. Installation',
    content: (
      <div>
        <h4 className="text-md font-semibold text-slate-200 mb-2">3.1 Prerequisites</h4>
        <div className="overflow-x-auto mb-6">
          <table className="min-w-full divide-y divide-slate-800 text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-2 pr-4 font-semibold">Requirement</th>
                <th className="py-2 px-4 font-semibold">Minimum</th>
                <th className="py-2 pl-4 font-semibold">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              <tr>
                <td className="py-2 pr-4">Python</td>
                <td className="py-2 px-4">3.10+</td>
                <td className="py-2 pl-4">3.12 recommended</td>
              </tr>
              <tr>
                <td className="py-2 pr-4">Ollama</td>
                <td className="py-2 px-4">Latest</td>
                <td className="py-2 pl-4">Local inference; optional — kelan works deterministically without it</td>
              </tr>
              <tr>
                <td className="py-2 pr-4">eBPF shield</td>
                <td className="py-2 px-4">—</td>
                <td className="py-2 pl-4">Linux + root / CAP_SYS_ADMIN required; macOS falls back to software simulation</td>
              </tr>
            </tbody>
          </table>
        </div>
        <h4 className="text-md font-semibold text-slate-200 mb-2">3.2 Install from Source (recommended)</h4>
        <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto mb-4">
{`git clone https://github.com/Tanush-Jain/kelan.git kelan
cd kelan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .`}
        </pre>
        <p className="text-slate-300 mb-4">Install optional SCA/IaC tooling so the plugins can run natively:</p>
        <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto mb-6">
{`pip install pip-audit
brew install osv-scanner
brew install tfsec checkov`}
        </pre>
        <h4 className="text-md font-semibold text-slate-200 mb-2">3.3 Docker</h4>
        <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto mb-4">
{`docker build --target dast -t kelan-dast .
docker build --target full -t kelan-all .`}
        </pre>
        <h4 className="text-md font-semibold text-slate-200 mb-2">3.4 Verify the Installation</h4>
        <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
{`kelan doctor`}
        </pre>
      </div>
    )
  },
  {
    id: 'quickstart',
    title: '4. Quick Start',
    content: (
      <div>
        <p className="text-slate-300 mb-4">One command, three target kinds — kelan auto-detects and routes to the right plugins:</p>
        <div className="space-y-4">
          <div>
            <h5 className="font-semibold text-slate-200">4.1 Scan a URL (DAST)</h5>
            <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
{`kelan run https://www.erasurehq.in/ --only DAST --show --json report.json`}
            </pre>
          </div>
          <div>
            <h5 className="font-semibold text-slate-200">4.2 Scan a local codebase (SAST + SCA)</h5>
            <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
{`kelan run ./kelan --only sast,sca --show`}
            </pre>
          </div>
          <div>
            <h5 className="font-semibold text-slate-200">4.3 Scan a remote git repository</h5>
            <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
{`kelan run https://github.com/org/repo.git --only sast,sca --sarif out.sarif`}
            </pre>
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'cli',
    title: '5. CLI Reference',
    content: (
      <div>
        <h4 className="text-md font-semibold text-slate-200 mb-2">5.1 kelan — interactive menu</h4>
        <p className="text-slate-300 mb-4">
          Running <code>kelan</code> with no arguments opens a styled interactive menu for quick access to scans.
        </p>
        <h4 className="text-md font-semibold text-slate-200 mb-2">5.2 Command-line arguments</h4>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-800 text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-2 pr-4 font-semibold">Flag</th>
                <th className="py-2 px-4 font-semibold">Type</th>
                <th className="py-2 pl-4 font-semibold">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">--only</td>
                <td className="py-2 px-4 text-xs">list</td>
                <td className="py-2 pl-4">Run only specified plugins (e.g. sast, sca)</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">--skip</td>
                <td className="py-2 px-4 text-xs">list</td>
                <td className="py-2 pl-4">Skip specified plugins during execution</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">--json</td>
                <td className="py-2 px-4 text-xs">path</td>
                <td className="py-2 pl-4">Output findings to a JSON file</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">--sarif</td>
                <td className="py-2 px-4 text-xs">path</td>
                <td className="py-2 pl-4">Output findings in SARIF 2.1.0 format</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    )
  },
  {
    id: 'plugins',
    title: '6. Plugin System & Scheduler',
    content: (
      <div>
        <p className="text-slate-300 mb-4">
          Every capability is a plugin. Plugins declare what target kinds they apply to, what plugins they depend on, and they exchange data through a shared context. The Scheduler orders them topologically, runs them, and merges all findings into one dataset.
        </p>
        <h4 className="text-md font-semibold text-slate-200 mb-2">6.1 Writing a plugin</h4>
        <p className="text-slate-300">
          Create a class inheriting from <code>ScanPlugin</code>, implement <code>run(self, ctx)</code> and add its path to `DEFAULT_PLUGIN_MODULES` in `kelan/plugins/__init__.py`.
        </p>
      </div>
    )
  },
  {
    id: 'engines',
    title: '7. Engines',
    content: (
      <div>
        <div className="space-y-4">
          <div>
            <h5 className="font-semibold text-slate-200">7.1 SAST</h5>
            <p className="text-slate-300 text-sm">AST-aware static analysis. Code is parsed with tree-sitter into semantic chunks for Python, JS, TS and TSX, then analyzed by the local LLM.</p>
          </div>
          <div>
            <h5 className="font-semibold text-slate-200">7.2 DAST</h5>
            <p className="text-slate-300 text-sm">Dynamic application security testing against live URLs. Detection is 100% deterministic; the LLM only refines wording.</p>
          </div>
          <div>
            <h5 className="font-semibold text-slate-200">7.3 SCA</h5>
            <p className="text-slate-300 text-sm">Software composition analysis of dependencies. Fully deterministic — no LLM involved.</p>
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'llm',
    title: '8. LLM Integration',
    content: (
      <div>
        <h4 className="text-md font-semibold text-slate-200 mb-2">8.1 Ollama Setup</h4>
        <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto mb-4">
{`ollama pull qwen2.5-coder:latest`}
        </pre>
        <h4 className="text-md font-semibold text-slate-200 mb-2">8.2 The Category-Lock</h4>
        <p className="text-slate-300">
          Strict prompt-based restriction that keeps local model rewordings within the deterministic category, preventing CWE/remediation hallucinations.
        </p>
      </div>
    )
  },
  {
    id: 'reports',
    title: '9. Reports & CI Integration',
    content: (
      <div>
        <p className="text-slate-300 mb-4">Export scan results to standard formats for pipeline integration:</p>
        <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto space-y-2">
{`kelan run <target> --json report.json
kelan run <target> --sarif report.sarif
kelan run <target> --html report.html`}
        </pre>
      </div>
    )
  },
  {
    id: 'methodology',
    title: '10. Methodology & Design Rules',
    content: (
      <div>
        <p className="text-slate-300">
          Unified design philosophy: AI is strictly advisory, scans are deterministic, findings must be backed by evidence, port scans must be opt-in connect-only, and outputs must remain fully offline and zero-telemetry.
        </p>
      </div>
    )
  },
  {
    id: 'testing',
    title: '11. Testing',
    content: (
      <div>
        <p className="text-slate-300 mb-4">Run the test suite using pytest:</p>
        <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto">
{`.venv/bin/pytest`}
        </pre>
      </div>
    )
  },
  {
    id: 'limitations',
    title: '12. Limitations',
    content: (
      <div>
        <p className="text-slate-300">
          Kelan is local-first: SAST runs per-chunk without global call graph; DAST uses static HTML parsing without browser JS execution; eBPF requires root/Linux environments.
        </p>
      </div>
    )
  },
  {
    id: 'roadmap',
    title: '13. Roadmap & Checklist',
    content: (
      <div>
        <p className="text-slate-300">
          Planned additions: dedicated endpoints analyzer (broken links), auth-aware DAST crawling, concurrency data-race checkers, and native release packages.
        </p>
      </div>
    )
  },
  {
    id: 'aicontrib',
    title: '14. AI-Assisted Development Context',
    content: (
      <div>
        <p className="text-slate-300">
          Kelan is designed to be onboarded cleanly by AI developer agents. Core behavior rules and verified states are persisted in local workspace guides like `SOUL.md`.
        </p>
      </div>
    )
  },
  {
    id: 'glossary',
    title: '15. Glossary',
    content: (
      <div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-800 text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-2 pr-4 font-semibold">Term</th>
                <th className="py-2 pl-4 font-semibold">Meaning</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">CWE</td>
                <td className="py-2 pl-4">Common Weakness Enumeration - vulnerability catalog</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">SAST</td>
                <td className="py-2 pl-4">Static Application Security Testing</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">DAST</td>
                <td className="py-2 pl-4">Dynamic Application Security Testing</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    )
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'scanner' | 'docs' | 'pqc'>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [docsSearch, setDocsSearch] = useState('');
  const [docsActiveSection, setDocsActiveSection] = useState('overview');

  // Scanner Simulator States
  const [scanTarget, setScanTarget] = useState('https://testaspnet.vulnweb.com/login.aspx');
  const [scanType, setScanType] = useState('dast');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanElapsedTime, setScanElapsedTime] = useState(0);
  const [scanLogs, setScanLogs] = useState<string[]>([
    '[INIT] Cyber-defense core initialized.',
    '[eBPF] XDP packet filter listening on port 9999...'
  ]);
  const [vulnData, setVulnData] = useState([
    { name: 'CRITICAL', value: 3, color: SEVERITIES.CRITICAL.color },
    { name: 'HIGH', value: 8, color: SEVERITIES.HIGH.color },
    { name: 'MEDIUM', value: 14, color: SEVERITIES.MEDIUM.color },
    { name: 'LOW', value: 25, color: SEVERITIES.LOW.color }
  ]);
  const [cweData, setCweData] = useState([
    { name: 'CWE-89 (SQLi)', value: 12 },
    { name: 'CWE-79 (XSS)', value: 9 },
    { name: 'CWE-22 (Path)', value: 6 },
    { name: 'CWE-200 (Info)', value: 15 },
    { name: 'CWE-639 (IDOR)', value: 4 }
  ]);

  // System Metric State loops (simulate fluctuating metrics)
  const [cpu, setCpu] = useState(24);
  const [ram, setRam] = useState(48);
  const [disk, setDisk] = useState(62);
  const [inferenceSpeed, setInferenceSpeed] = useState(28.4);
  const [packetsDropped, setPacketsDropped] = useState(1480);
  const [activeConns, setActiveConns] = useState(42);

  // Sparkline history data for visualization
  const [cpuHistory, setCpuHistory] = useState([20, 22, 25, 24, 23, 26, 24]);
  const [ramHistory, setRamHistory] = useState([47, 48, 48, 48, 48, 49, 48]);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Fluctuating metric simulator
  useEffect(() => {
    const timer = setInterval(() => {
      setCpu(prev => {
        const next = Math.max(10, Math.min(95, prev + Math.floor(Math.random() * 7) - 3));
        setCpuHistory(hist => [...hist.slice(1), next]);
        return next;
      });
      setRam(prev => {
        const next = Math.max(30, Math.min(90, prev + Math.floor(Math.random() * 3) - 1));
        setRamHistory(hist => [...hist.slice(1), next]);
        return next;
      });
      setDisk(prev => Math.max(20, Math.min(99, prev + (Math.random() > 0.95 ? 1 : 0))));
      setInferenceSpeed(prev => parseFloat(Math.max(20, Math.min(45, prev + (Math.random() * 2 - 1))).toFixed(1)));
      setPacketsDropped(prev => prev + (Math.random() > 0.7 ? Math.floor(Math.random() * 5) : 0));
      setActiveConns(prev => Math.max(5, Math.min(150, prev + Math.floor(Math.random() * 5) - 2)));
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  // Scan elapsed time and progress simulator
  useEffect(() => {
    let timer: any;
    if (isScanning) {
      timer = setInterval(() => {
        setScanElapsedTime(prev => prev + 1);
        setScanProgress(prev => {
          if (prev >= 100) {
            setIsScanning(false);
            // Append final log
            setScanLogs(logs => [
              ...logs,
              `[SUCCESS] Scan complete. Found: 1 CRITICAL, 3 HIGH, 4 MEDIUM findings.`,
              `[REPORT] SARIF/JSON report saved to target directory.`
            ]);
            // Update charts slightly
            setVulnData(prev => [
              { name: 'CRITICAL', value: prev[0].value + 1, color: SEVERITIES.CRITICAL.color },
              { name: 'HIGH', value: prev[1].value + 3, color: SEVERITIES.HIGH.color },
              { name: 'MEDIUM', value: prev[2].value + 4, color: SEVERITIES.MEDIUM.color },
              { name: 'LOW', value: prev[3].value + 2, color: SEVERITIES.LOW.color }
            ]);
            return 100;
          }
          const step = Math.floor(Math.random() * 15) + 5;
          const next = Math.min(100, prev + step);

          // Add random scanning log items
          if (next > prev) {
            const simulatedLogs = [
              `[SCANNER] Auditing directory structure...`,
              `[SAST] Tree-sitter semantic chunking initiated...`,
              `[OLLAMA] Evaluating chunk 14/158... (Gemma 4)`,
              `[DAST] Crawling form routes... discovered 12 input params`,
              `[DAST] Form validation payload sent: <img src=x onerror=alert(1)>`,
              `[DAST] Target returned 200 Reflection for payload: bypass verified!`,
              `[eBPF] Syn flood monitoring: no anomalies detected.`,
              `[SCA] Parsing requirements.txt... matched 42 dependency locks.`,
              `[CHAINS] Correlating static code injection to dynamic crawler outputs...`
            ];
            const logItem = simulatedLogs[Math.floor(Math.random() * simulatedLogs.length)];
            setScanLogs(logs => [...logs, logItem]);
          }

          return next;
        });
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [isScanning]);

  // Terminal scroll to bottom
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanLogs]);

  const handleStartScan = () => {
    setIsScanning(true);
    setScanProgress(0);
    setScanElapsedTime(0);
    setScanLogs([
      `[INIT] Scanning initiated against target: ${scanTarget}`,
      `[CONFIG] Scan Type: ${scanType.toUpperCase()} | Model: qwen2.5-coder`,
      `[PORTS] Running TCP connect scan on target ports...`
    ]);
  };

  const filteredDocs = DOCS_SECTIONS.filter(sec => 
    sec.title.toLowerCase().includes(docsSearch.toLowerCase()) ||
    sec.id.toLowerCase().includes(docsSearch.toLowerCase())
  );

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100 cyber-grid overflow-hidden font-sans">
      
      {/* Sidebar Navigation */}
      <motion.aside 
        animate={{ width: sidebarOpen ? 260 : 70 }}
        className="flex flex-col bg-slate-900 border-r border-slate-800 shrink-0 h-screen sticky top-0 z-50 overflow-hidden"
      >
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20 text-blue-400">
              <Shield className="w-5 h-5" />
            </div>
            {sidebarOpen && (
              <motion.span 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="font-bold bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent text-lg tracking-wider"
              >
                KELAN
              </motion.span>
            )}
          </div>
          <button 
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 border border-slate-700"
          >
            {sidebarOpen ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: Activity },
            { id: 'scanner', label: 'Scan Console', icon: Terminal },
            { id: 'docs', label: 'Documentation', icon: BookOpen },
            { id: 'pqc', label: 'PQC Handshake', icon: Key },
          ].map(item => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id as any)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border text-sm transition-all duration-200 ${
                  active 
                    ? 'bg-blue-600/10 border-blue-500/30 text-blue-400 shadow-[inset_0_0_12px_rgba(59,130,246,0.1)]' 
                    : 'bg-transparent border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-blue-400' : 'text-slate-400'}`} />
                {sidebarOpen && <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }}>{item.label}</motion.span>}
              </button>
            );
          })}
        </nav>

        <div className="p-3 border-t border-slate-800 text-xs text-slate-500 font-mono overflow-hidden">
          {sidebarOpen && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping"></span>
                <span>SECURE MODE ENABLED</span>
              </div>
              <p className="mt-1">v0.4.0 (Zero-Telemetry)</p>
            </motion.div>
          )}
        </div>
      </motion.aside>

      {/* Main Command Center Body */}
      <div className="flex-1 flex flex-col min-h-screen overflow-y-auto">
        
        {/* Top Navbar */}
        <header className="flex items-center justify-between px-6 py-4 bg-slate-900/60 backdrop-blur border-b border-slate-800 sticky top-0 z-40">
          <div>
            <h2 className="text-lg font-bold tracking-tight text-slate-200">
              {activeTab === 'dashboard' && 'Security Command Center'}
              {activeTab === 'scanner' && 'Interactive Scan Console'}
              {activeTab === 'docs' && 'Kelan Documentation'}
              {activeTab === 'pqc' && 'Post-Quantum Key Exchange'}
            </h2>
            <p className="text-xs text-slate-400">Zero-knowledge local security auditor</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-500"></span>
              <span>Ollama: qwen2.5-coder</span>
            </div>
            <div className="px-3 py-1.5 rounded-full bg-emerald-950/20 border border-emerald-900/30 text-xs text-emerald-400 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span>eBPF Active</span>
            </div>
          </div>
        </header>

        {/* Content Wrapper */}
        <main className="flex-1 p-6 space-y-6">
          <AnimatePresence mode="wait">
            
            {/* VIEW: DASHBOARD */}
            {activeTab === 'dashboard' && (
              <motion.div 
                key="dashboard"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="space-y-6"
              >
                {/* 1. Metrics Ribbon */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  
                  {/* CPU Widget */}
                  <div className="bg-slate-900/60 backdrop-blur p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-all duration-300 relative group overflow-hidden">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-xs font-semibold text-slate-400 font-mono">CPU UTILIZATION</span>
                      <Cpu className="w-4 h-4 text-blue-400" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold tracking-tight font-mono">{cpu}%</span>
                      <span className="text-xs text-slate-500 font-mono">4 cores active</span>
                    </div>
                    {/* Sparkline Visual */}
                    <div className="mt-3 flex items-end gap-1 h-6">
                      {cpuHistory.map((val, i) => (
                        <div 
                          key={i} 
                          className="bg-blue-500/30 group-hover:bg-blue-500/50 rounded-sm w-full transition-all duration-300"
                          style={{ height: `${val}%` }}
                        />
                      ))}
                    </div>
                  </div>

                  {/* RAM Widget */}
                  <div className="bg-slate-900/60 backdrop-blur p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-all duration-300 relative group overflow-hidden">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-xs font-semibold text-slate-400 font-mono">MEMORY IN USE</span>
                      <Memory className="w-4 h-4 text-indigo-400" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold tracking-tight font-mono">{ram}%</span>
                      <span className="text-xs text-slate-500 font-mono">7.6 GB / 16.0 GB</span>
                    </div>
                    {/* Sparkline Visual */}
                    <div className="mt-3 flex items-end gap-1 h-6">
                      {ramHistory.map((val, i) => (
                        <div 
                          key={i} 
                          className="bg-indigo-500/30 group-hover:bg-indigo-500/50 rounded-sm w-full transition-all duration-300"
                          style={{ height: `${val}%` }}
                        />
                      ))}
                    </div>
                  </div>

                  {/* Ollama Engine Status */}
                  <div className="bg-slate-900/60 backdrop-blur p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-all duration-300 relative group overflow-hidden">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-xs font-semibold text-slate-400 font-mono">OLLAMA INFERENCE</span>
                      <Server className="w-4 h-4 text-purple-400" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold tracking-tight font-mono">{inferenceSpeed}</span>
                      <span className="text-xs text-slate-500 font-mono">tokens/sec</span>
                    </div>
                    <div className="mt-3 text-[10px] font-mono text-slate-500">
                      MODEL: qwen2.5-coder:latest (LOCAL)
                    </div>
                  </div>

                  {/* eBPF Network Shield */}
                  <div className="bg-slate-900/60 backdrop-blur p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-all duration-300 relative group overflow-hidden">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-xs font-semibold text-slate-400 font-mono">eBPF SHIELD STATUS</span>
                      <Network className="w-4 h-4 text-emerald-400" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold tracking-tight font-mono text-emerald-400">+{packetsDropped}</span>
                      <span className="text-xs text-slate-500 font-mono">pkts filtered</span>
                    </div>
                    <div className="mt-3 text-[10px] font-mono text-slate-500 flex justify-between">
                      <span>CONNS: {activeConns}</span>
                      <span className="text-emerald-500 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                        LIVE
                      </span>
                    </div>
                  </div>
                </div>

                {/* 2. Grid Content: Charts & Active scans */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  
                  {/* Vulnerability Analytics */}
                  <div className="bg-slate-900/60 backdrop-blur p-5 rounded-xl border border-slate-800 col-span-2 space-y-6">
                    <div className="flex justify-between items-center">
                      <h3 className="text-sm font-bold tracking-wider text-slate-300 font-mono">VULNERABILITY ANALYTICS</h3>
                      <span className="text-xs text-slate-500">Last updated: 30 days</span>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 h-[220px]">
                      
                      {/* Donut Chart */}
                      <div className="flex flex-col items-center justify-center">
                        <span className="text-xs font-mono text-slate-400 mb-2">Findings by Severity</span>
                        <ResponsiveContainer width="100%" height={160}>
                          <PieChart>
                            <Pie
                              data={vulnData}
                              cx="50%"
                              cy="50%"
                              innerRadius={45}
                              outerRadius={65}
                              paddingAngle={4}
                              dataKey="value"
                            >
                              {vulnData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                              ))}
                            </Pie>
                            <Tooltip 
                              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                              labelClassName="text-slate-300"
                            />
                          </PieChart>
                        </ResponsiveContainer>
                        <div className="flex gap-3 text-[10px] font-mono text-slate-400">
                          {vulnData.map((d, i) => (
                            <span key={i} className="flex items-center gap-1">
                              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }}></span>
                              {d.name} ({d.value})
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Bar Chart */}
                      <div className="flex flex-col items-center justify-center">
                        <span className="text-xs font-mono text-slate-400 mb-2">Top CWE Targets</span>
                        <ResponsiveContainer width="100%" height={170}>
                          <BarChart data={cweData}>
                            <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                            <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                            <Tooltip 
                              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                              labelClassName="text-slate-300"
                            />
                            <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>

                    </div>
                  </div>

                  {/* Active Scans & Actions */}
                  <div className="bg-slate-900/60 backdrop-blur p-5 rounded-xl border border-slate-800 space-y-4">
                    <h3 className="text-sm font-bold tracking-wider text-slate-300 font-mono">ACTIVE SCANNER MODULES</h3>
                    
                    {/* Scanning block */}
                    <div className="space-y-4">
                      {isScanning ? (
                        <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-lg space-y-3 relative overflow-hidden">
                          <div className="flex justify-between text-xs font-mono">
                            <span className="text-blue-400 flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping"></span>
                              RUNNING: {scanType.toUpperCase()}
                            </span>
                            <span className="text-slate-400">{scanProgress}%</span>
                          </div>
                          
                          {/* Progress bar container */}
                          <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <motion.div 
                              className="bg-gradient-to-r from-blue-500 to-indigo-500 h-full"
                              style={{ width: `${scanProgress}%` }}
                            />
                          </div>

                          <div className="flex justify-between text-[10px] font-mono text-slate-500">
                            <span>Elapsed: {scanElapsedTime}s</span>
                            <span>Target: {scanTarget.length > 25 ? scanTarget.slice(0, 25) + '...' : scanTarget}</span>
                          </div>
                        </div>
                      ) : (
                        <div className="bg-slate-950/40 border border-slate-800 p-4 rounded-lg text-center text-xs text-slate-500 font-mono">
                          No active scans running. Trigger a scan from the scan console or quick actions.
                        </div>
                      )}

                      {/* Quick Actions Panel */}
                      <div className="space-y-2">
                        <button 
                          onClick={() => { setActiveTab('scanner'); }}
                          className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-slate-100 font-semibold text-xs border border-blue-500 shadow-[0_4px_12px_rgba(59,130,246,0.2)] flex items-center justify-center gap-2 transition-all duration-200"
                        >
                          <Play className="w-3.5 h-3.5" />
                          LAUNCH SCAN ENGINE
                        </button>
                        <div className="grid grid-cols-2 gap-2">
                          <button className="py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs border border-slate-700 flex items-center justify-center gap-1.5 transition-all duration-200">
                            <Download className="w-3.5 h-3.5" />
                            SARIF Report
                          </button>
                          <button className="py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs border border-slate-700 flex items-center justify-center gap-1.5 transition-all duration-200">
                            <RefreshCw className="w-3.5 h-3.5" />
                            Update Models
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 3. Threat Log terminal */}
                <div className="bg-slate-900/60 backdrop-blur p-5 rounded-xl border border-slate-800 space-y-3">
                  <div className="flex justify-between items-center">
                    <h3 className="text-sm font-bold tracking-wider text-slate-300 font-mono">LIVE THREAT FEED</h3>
                    <span className="text-[10px] font-mono text-slate-500">PORT: 9999 (eBPF packet block)</span>
                  </div>
                  
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 h-[160px] overflow-y-auto font-mono text-xs text-slate-400 terminal-scroll space-y-1">
                    {scanLogs.map((log, idx) => {
                      let color = 'text-slate-400';
                      if (log.includes('[INIT]') || log.includes('[CONFIG]')) color = 'text-blue-400';
                      if (log.includes('[SUCCESS]') || log.includes('[REPORT]')) color = 'text-emerald-400';
                      if (log.includes('[eBPF]')) color = 'text-amber-500';
                      if (log.includes('[SCANNER]') || log.includes('[OLLAMA]')) color = 'text-purple-400';
                      return (
                        <div key={idx} className={color}>
                          {log}
                        </div>
                      );
                    })}
                    <div ref={logsEndRef} />
                  </div>
                </div>

              </motion.div>
            )}

            {/* VIEW: SCANNER CONSOLE */}
            {activeTab === 'scanner' && (
              <motion.div 
                key="scanner"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="grid grid-cols-1 lg:grid-cols-3 gap-6"
              >
                {/* Configuration Console */}
                <div className="bg-slate-900/60 backdrop-blur p-5 rounded-xl border border-slate-800 space-y-5">
                  <h3 className="text-sm font-bold tracking-wider text-slate-300 font-mono">SCAN CONFIGURATION</h3>
                  
                  <div className="space-y-4">
                    
                    {/* Target Selector */}
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-slate-400 font-mono">SCAN TARGET</label>
                      <input 
                        type="text" 
                        value={scanTarget}
                        onChange={(e) => setScanTarget(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-blue-500 transition-colors duration-200"
                        placeholder="e.g. ./kelan or https://example.com"
                      />
                    </div>

                    {/* Scan Type selector */}
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-slate-400 font-mono">SCAN TYPE</label>
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          { id: 'dast', label: 'DAST (Dynamic)' },
                          { id: 'sast', label: 'SAST (Static)' },
                        ].map(type => (
                          <button
                            key={type.id}
                            onClick={() => setScanType(type.id)}
                            className={`py-2 rounded-lg border text-xs font-mono transition-all duration-200 ${
                              scanType === type.id 
                                ? 'bg-blue-600/10 border-blue-500 text-blue-400' 
                                : 'bg-transparent border-slate-800 text-slate-400 hover:border-slate-700'
                            }`}
                          >
                            {type.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <button 
                      onClick={handleStartScan}
                      disabled={isScanning}
                      className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-slate-100 font-semibold text-xs border border-blue-500 shadow-[0_4px_12px_rgba(59,130,246,0.2)] flex items-center justify-center gap-2 transition-all duration-200"
                    >
                      <Play className="w-3.5 h-3.5" />
                      {isScanning ? 'RUNNING SCAN...' : 'START SCAN ENGINE'}
                    </button>

                  </div>
                </div>

                {/* Scan Progress & Logs */}
                <div className="bg-slate-900/60 backdrop-blur p-5 rounded-xl border border-slate-800 lg:col-span-2 space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-sm font-bold tracking-wider text-slate-300 font-mono">REAL-TIME CONSOLE OUTPUT</h3>
                    <div className="flex gap-2">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-400 font-mono">
                        CONCURRENCY: 2
                      </span>
                    </div>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 h-[320px] overflow-y-auto font-mono text-xs text-slate-300 space-y-1 terminal-scroll">
                    {scanLogs.map((log, idx) => {
                      let color = 'text-slate-400';
                      if (log.includes('[INIT]') || log.includes('[CONFIG]')) color = 'text-blue-400';
                      if (log.includes('[SUCCESS]') || log.includes('[REPORT]')) color = 'text-emerald-400';
                      if (log.includes('[eBPF]')) color = 'text-amber-500';
                      if (log.includes('[SCANNER]') || log.includes('[OLLAMA]')) color = 'text-purple-400';
                      return (
                        <div key={idx} className={color}>
                          {log}
                        </div>
                      );
                    })}
                    <div ref={logsEndRef} />
                  </div>
                </div>

              </motion.div>
            )}

            {/* VIEW: DOCUMENTATION */}
            {activeTab === 'docs' && (
              <motion.div 
                key="docs"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="grid grid-cols-1 lg:grid-cols-4 gap-6"
              >
                
                {/* Search & Sidebar list of Sections */}
                <div className="bg-slate-900/60 backdrop-blur p-4 rounded-xl border border-slate-800 space-y-4 self-start">
                  
                  {/* Search Input */}
                  <div className="relative">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input 
                      type="text" 
                      placeholder="Search sections..."
                      value={docsSearch}
                      onChange={(e) => setDocsSearch(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 outline-none focus:border-blue-500 transition-colors duration-200"
                    />
                  </div>

                  {/* Sections List */}
                  <div className="space-y-1">
                    {filteredDocs.map((sec, idx) => (
                      <button
                        key={sec.id}
                        onClick={() => setDocsActiveSection(sec.id)}
                        className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono transition-all duration-200 ${
                          docsActiveSection === sec.id 
                            ? 'bg-blue-600/10 text-blue-400 font-semibold' 
                            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                        }`}
                      >
                        {sec.title}
                      </button>
                    ))}
                  </div>

                </div>

                {/* Content Panel */}
                <div className="bg-slate-900/60 backdrop-blur p-6 rounded-xl border border-slate-800 lg:col-span-3 min-h-[480px]">
                  {DOCS_SECTIONS.map((sec) => {
                    if (sec.id !== docsActiveSection) return null;
                    return (
                      <motion.div 
                        key={sec.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="space-y-4"
                      >
                        <h2 className="text-xl font-bold tracking-tight text-slate-100 pb-2 border-b border-slate-800">
                          {sec.title}
                        </h2>
                        <div className="text-slate-300 text-sm leading-relaxed prose prose-invert max-w-none">
                          {sec.content}
                        </div>
                      </motion.div>
                    );
                  })}
                </div>

              </motion.div>
            )}

            {/* VIEW: PQC HANDSHAKE */}
            {activeTab === 'pqc' && (
              <motion.div 
                key="pqc"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="grid grid-cols-1 lg:grid-cols-3 gap-6"
              >
                
                {/* Stats Panel */}
                <div className="bg-slate-900/60 backdrop-blur p-5 rounded-xl border border-slate-800 space-y-4">
                  <h3 className="text-sm font-bold tracking-wider text-slate-300 font-mono">PQC TELEMETRY</h3>
                  
                  <div className="space-y-4">
                    <div className="bg-slate-950/60 border border-slate-800 p-4 rounded-lg">
                      <div className="text-[10px] font-mono text-slate-500 mb-1">KEY EXCHANGED ALGORITHM</div>
                      <div className="text-lg font-bold text-indigo-400 font-mono">ML-KEM-768</div>
                      <div className="text-[10px] text-slate-400 mt-1">Post-Quantum Cryptography Handshake</div>
                    </div>

                    <div className="bg-slate-950/60 border border-slate-800 p-4 rounded-lg">
                      <div className="text-[10px] font-mono text-slate-500 mb-1">SESSION KEYS DERIVED</div>
                      <div className="text-lg font-bold text-emerald-400 font-mono">Active (32-byte)</div>
                      <div className="text-[10px] text-slate-400 mt-1">Symmetric key exchange derived via HKDF</div>
                    </div>
                  </div>
                </div>

                {/* Handshake Exchange Logger */}
                <div className="bg-slate-900/60 backdrop-blur p-5 rounded-xl border border-slate-800 lg:col-span-2 space-y-3">
                  <h3 className="text-sm font-bold tracking-wider text-slate-300 font-mono">ML-KEM-768 HANDSHAKE LOG</h3>
                  
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 h-[300px] overflow-y-auto font-mono text-xs text-slate-400 terminal-scroll space-y-1">
                    <div>[SYSTEM] Listening on UDP port 9999 for post-quantum packets...</div>
                    <div className="text-indigo-400">[MLKEM] Client connected: generating ML-KEM encapsulation...</div>
                    <div className="text-indigo-400">[MLKEM] Shared secret negotiated.</div>
                    <div className="text-emerald-400">[HKDF] Derived session key: 32 bytes derived securely.</div>
                  </div>
                </div>

              </motion.div>
            )}

          </AnimatePresence>
        </main>
      </div>

    </div>
  );
}
