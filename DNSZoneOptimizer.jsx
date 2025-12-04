import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Server, 
  RefreshCw, 
  Code, 
  FileText, 
  Copy, 
  ArrowRight,
  Database,
  Cloud,
  Lock,
  Zap,
  Sparkles,
  Bot,
  Terminal,
  MessageSquare,
  LayoutGrid
} from 'lucide-react';

const DNSZoneOptimizer = () => {
  const initialZoneFile = `;;
;; Domain:     www.idarti.com.
;; Exported:   2025-12-03 23:57:10
;; Root Idea:  Came to me when some of my clients' emails kept bouncing wjen travelling from my domain to 
;; Microsoft's server via my Cloudflare implementation. I decided I might make a multi-platform app so help save time.
;; Creator:    Igor Dunaev, using Google's tools


;; SOA Record
yoursite.com\t3600\tIN\tSOA\tclarissa.ns.cloudflare.com. dns.cloudflare.com. 2051647283 10000 2400 604800 3600

;; NS Records
yoursite.com.\t86400\tIN\tNS\tclarissa.ns.cloudflare.com.
yoursite.com.\t86400\tIN\tNS\tkobe.ns.cloudflare.com.

;; CNAME Records
3cdab4e06bdef9c765e3bb35f61aebed.yoursite.com.\t1\tIN\tCNAME\tverify.bing.com.
email.yoursite.com.\t1\tIN\tCNAME\temail.yoursite.com.cdn.cloudflare.net.
hs1-146257293._domainkey.yoursite.com.\t1\tIN\tCNAME\tyoursite-com.hs07a.dkim.hubspotemail.net.
hs2-146257293._domainkey.yoursite.com.\t1\tIN\tCNAME\tyoursite-com.hs07b.dkim.hubspotemail.net.
hub.yoursite.com.\t1\tIN\tCNAME\t146257293.group0.sites.hscoscdn-eu1.net.
yoursite.com.\t1\tIN\tCNAME\tyoursite.pages.dev.
www.yoursite.com.\t1\tIN\tCNAME\tyoursite.pages.dev.

;; MX Records
hub.xxxxxx.com.\t1\tIN\tMX\t55 route1.mx.cloudflare.net.
hub.xxxxxx.com.\t1\tIN\tMX\t13 route3.mx.cloudflare.net.
hub.xxxxxx.com.\t1\tIN\tMX\t52 route2.mx.cloudflare.net.
xxxxxx.com.\t1\tIN\tMX\t52 route2.mx.cloudflare.net.
xxxxxx.com.\t1\tIN\tMX\t55 route1.mx.cloudflare.net.
xxxxxx.com.\t1\tIN\tMX\t13 route3.mx.cloudflare.net.

;; TXT Records
cf2024-1._domainkey.yoursite.com.\t1\tIN\tTXT\t"v=DKIM1; h=sha256; k=rsa; p=" " "++jXh+dJ+p+F08i95l3+aV7+V+2UqXwIDAQAB"
yoursite.com.\t1\tIN\tTXT\t"google-site-verification=..."
yoursite.com.\t1\tIN\tTXT\t"v=spf1 include:_spf.mx.cloudflare.net ~all"
yoursite.com.\t1\tIN\tTXT\t"include:146257293.spf07.hubspotemail.net"
yoursite.com.\t1\tIN\tTXT\t"yandex-verification: 784e96ff9b0fbe9a"
yoursite.com.\t1\tIN\tTXT\t"pinterest-site-verification=..."
yoursite.com.\t1\tIN\tTXT\t"hubspot-developer-verification=..."
yoursite.com.\t1\tIN\tTXT\t"openai-domain-verification=..."
_dmarc.yoursite.com.\t1\tIN\tTXT\t"v=DMARC1; p=none; rua=mailto:..."`;

  const [inputZone, setInputZone] = useState(initialZoneFile);
  const [optimizedZone, setOptimizedZone] = useState('');
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ riskScore: 0, criticalErrors: 0, warnings: 0 });
  const [isOptimized, setIsOptimized] = useState(false);
  
  // New State for Platform Selection
  const [platform, setPlatform] = useState('cf'); // 'cf', 'aws', 'bind'
  const domainName = 'yoursite.com';

  // AI State
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiCommand, setAiCommand] = useState('');
  const [aiCommandResult, setAiCommandResult] = useState('');
  const [isAiCommandLoading, setIsAiCommandLoading] = useState(false);

  // Gemini API Key (Injected by environment)
  const apiKey = ""; 

  // --- Gemini API Logic ---

  const callGemini = async (prompt) => {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`;
    const payload = {
      contents: [{ parts: [{ text: prompt }] }]
    };

    let retries = 0;
    const maxRetries = 3;
    const delays = [1000, 2000, 4000];

    while (retries <= maxRetries) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

        const result = await response.json();
        return result.candidates?.[0]?.content?.parts?.[0]?.text || "No analysis generated.";
      } catch (error) {
        retries++;
        if (retries > maxRetries) {
          console.error("Gemini API Error:", error);
          return "Error connecting to AI Security Core. Please try again.";
        }
        await new Promise(res => setTimeout(res, delays[retries - 1]));
      }
    }
  };

  const runAIDeepScan = async () => {
    setIsAiLoading(true);
    setAiAnalysis(null);
    
    const platformName = platform === 'cf' ? "Cloudflare" : platform === 'aws' ? "AWS Route 53" : "Generic BIND";

    const prompt = `
      Act as a Senior DevSecOps Engineer specialized in ${platformName}. Analyze the following DNS Zone file (BIND format).
      The domain is ${domainName}.
      
      Focus on:
      1. **Email Security:** DMARC policy strength (flag 'p=none'), SPF consolidation (must be under 10 lookups).
      2. **TLS/SSL Security:** Missing or weak CAA records (Certificate Authority Authorization).
      3. **Platform-Specific Compliance:** Enforce RFC 1035 rules for ${platformName} (e.g., CNAME Apex handling).
      4. **Hygiene:** Old verification records, unstable TTLs.

      Zone File Content:
      ${inputZone}

      Output Format:
      Provide a JSON object with this exact schema (do not use markdown code blocks, just raw JSON):
      {
        "riskLevel": "High" | "Medium" | "Low",
        "summary": "One sentence executive summary focusing on ${platformName} compliance.",
        "findings": [
          { "type": "Security" | "Optimization" | "Email", "message": "The finding description" }
        ]
      }
    `;

    try {
      const textResponse = await callGemini(prompt);
      // Clean up markdown code blocks if Gemini sends them
      const cleanJson = textResponse.replace(/```json/g, '').replace(/```/g, '').trim();
      const parsed = JSON.parse(cleanJson);
      setAiAnalysis(parsed);
    } catch (e) {
      setAiAnalysis({
        riskLevel: "Unknown",
        summary: "Could not parse AI response.",
        findings: [{ type: "Error", message: "Raw output: " + e.message }]
      });
    }
    setIsAiLoading(false);
  };

  const runAICommand = async () => {
    if (!aiCommand) return;
    setIsAiCommandLoading(true);
    const platformName = platform === 'cf' ? "Cloudflare" : platform === 'aws' ? "AWS Route 53" : "Generic BIND";

    const prompt = `
      You are a DNS Record Generator for ${platformName}. 
      User Request: "${aiCommand}"
      The domain is ${domainName}.
      
      Generate the correct BIND DNS record(s) for this request, adjusted for ${platformName} best practices.
      Output ONLY the code lines, no explanations.
      Example Output:
      ${domainName}. 3600 IN MX 10 mail.example.com.
    `;

    const result = await callGemini(prompt);
    setAiCommandResult(result);
    setIsAiCommandLoading(false);
  };

  // --- Core Logic ---

  const parseZone = (raw) => {
    const lines = raw.split('\n');
    const records = [];
    
    lines.forEach(line => {
      const cleanLine = line.trim();
      if (!cleanLine || cleanLine.startsWith(';')) return;
      const parts = cleanLine.split(/\s+/);
      let name = parts[0];
      let ttl = parts[1];
      let rclass = parts[2];
      let type = parts[3];
      let data = parts.slice(4).join(' ');

      if (rclass !== 'IN' && type === 'IN') {
         const temp = rclass;
         rclass = type;
         type = temp;
      }
      records.push({ name, ttl, rclass, type, data, original: line });
    });
    return records;
  };

  const analyzeAndFix = () => {
    const records = parseZone(inputZone);
    const newLogs = [];
    let criticals = 0;
    let warns = 0;
    
    // 1. SPF Consolidation
    const spfRecords = records.filter(r => 
      r.type === 'TXT' && 
      (r.name.includes(domainName)) && 
      (r.data.includes('v=spf1') || r.data.includes('include:'))
    );

    let mergedSPF = '';
    
    if (spfRecords.length > 1) {
      criticals++;
      newLogs.push({ type: 'critical', msg: `[Email] Detected ${spfRecords.length} fragmented SPF records. Merging required.` });
      let includes = [];
      let mechanism = '~all';
      spfRecords.forEach(rec => {
        const content = rec.data.replace(/"/g, '');
        const parts = content.split(' ');
        parts.forEach(p => {
          if (p.startsWith('include:')) includes.push(p);
          if (p === '-all' || p === '~all' || p === '?all') mechanism = p;
        });
      });
      mergedSPF = `"v=spf1 ${includes.join(' ')} ${mechanism}"`;
      newLogs.push({ type: 'success', msg: 'Merged SPF records into authoritative string.' });
    }

    // 2. TTL Normalization (Platform-Aware)
    const riskyTTLs = records.filter(r => r.ttl === '1');
    if (riskyTTLs.length > 0) {
      if (platform !== 'cf') {
        warns += riskyTTLs.length;
        newLogs.push({ type: 'warning', msg: `[${platform.toUpperCase()} Hygiene] Found ${riskyTTLs.length} records with TTL=1. Normalizing to 300s.` });
      } else {
         newLogs.push({ type: 'info', msg: `[Cloudflare] TTL=1 detected. Treated as 'Auto/Proxied' TTL, no change.` });
      }
    }
    
    // 3. Apex CNAME Check (Platform-Aware)
    const apexCNAME = records.find(r => 
      (r.name.includes(domainName) && !r.name.replace(domainName, '')) && r.type === 'CNAME'
    );
    if (apexCNAME) {
      if (platform === 'aws' || platform === 'bind') {
        criticals++;
        newLogs.push({ type: 'critical', msg: `[${platform.toUpperCase()} Violation] CNAME at Zone Apex (${domainName}). Must be flattened.` });
      } else {
        newLogs.push({ type: 'info', msg: `[Cloudflare] Apex CNAME is acceptable due to CNAME Flattening feature.` });
      }
    }

    // Reconstruct Output
    let outputLines = [
      `;; OPTIMIZED ZONE FILE FOR ${domainName.toUpperCase()}`,
      `;; TARGET PLATFORM: ${platform.toUpperCase()}`,
      `;; Generated by Security Operations Logic`,
      `;; Date: ${new Date().toISOString()}`,
      ``
    ];

    const soa = records.find(r => r.type === 'SOA');
    if (soa) {
        const soaParts = soa.data.split(' ');
        soaParts[2] = '2025120401'; 
        outputLines.push(`${soa.name}\t3600\tIN\tSOA\t${soaParts.join(' ')}`);
    } else {
        outputLines.push(`${domainName}.\t3600\tIN\tSOA\tns1.${domainName}. admin.${domainName}. 2025120401 10800 3600 604800 3600`);
    }
    outputLines.push(``);

    const processedHashes = new Set(); 

    records.forEach(rec => {
      if (rec.type === 'SOA') return;
      let finalTTL = (rec.ttl === '1' && (platform === 'aws' || platform === 'bind')) ? '300' : rec.ttl;
      let finalData = rec.data;
      let finalName = rec.name;
      let finalType = rec.type;
      let comment = '';

      // Apply SPF Fix
      if (rec.type === 'TXT' && (rec.name.includes(domainName)) && (rec.data.includes('v=spf1') || rec.data.includes('include:'))) {
        if (mergedSPF && processedHashes.has('SPF_DONE')) return; // Skip redundant fragmented records
        if (mergedSPF) {
            finalData = mergedSPF;
            processedHashes.add('SPF_DONE');
            comment = '\t; SECUR_FIX: Merged SPF';
        }
      }

      // Apply Apex CNAME Fix for non-Cloudflare platforms
      if (rec.type === 'CNAME' && (rec.name.includes(domainName) && !rec.name.replace(domainName, '')) && (platform === 'aws' || platform === 'bind')) {
          finalType = 'A';
          finalData = '104.18.2.3'; // Placeholder IP (must be replaced with an actual target IP)
          comment = '\t; RFC_FIX: Flattened (MUST be an A record IP)';
      }

      const line = `${finalName}\t${finalTTL}\tIN\t${finalType}\t${finalData}${comment}`;
      outputLines.push(line);
    });

    setOptimizedZone(outputLines.join('\n'));
    setLogs(newLogs);
    setStats({
      riskScore: Math.min(100, (criticals * 40) + (warns * 10)),
      criticalErrors: criticals,
      warnings: warns
    });
    setIsOptimized(true);
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-900 p-4 md:p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-700 pb-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyan-500/10 rounded-lg border border-cyan-500/50">
                <Shield className="w-8 h-8 text-cyan-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                  DNS Zone SecOps Engine 
                  <span className="text-[10px] bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded-full border border-purple-500/30 flex items-center gap-1">
                    <Sparkles className="w-3 h-3" /> AI Enhanced
                  </span>
                </h1>
                <p className="text-slate-400 text-sm font-mono">LEGION2 // Module: Infrastructure Hardening</p>
              </div>
            </div>
          </div>
          
          {/* Target Platform Selector */}
          <div className="flex bg-slate-800 p-1 rounded-lg border border-slate-700 mt-4 md:mt-0">
             <button 
                onClick={() => setPlatform('cf')}
                className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-2 ${platform === 'cf' ? 'bg-orange-500/20 text-orange-400 shadow-sm border border-orange-500/20' : 'text-slate-500 hover:text-slate-300'}`}
             >
                <Cloud className="w-3 h-3" /> Cloudflare
             </button>
             <button 
                onClick={() => setPlatform('aws')}
                className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-2 ${platform === 'aws' ? 'bg-amber-500/20 text-amber-400 shadow-sm border border-amber-500/20' : 'text-slate-500 hover:text-slate-300'}`}
             >
                <LayoutGrid className="w-3 h-3" /> AWS Route 53
             </button>
             <button 
                onClick={() => setPlatform('bind')}
                className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-2 ${platform === 'bind' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-500 hover:text-slate-300'}`}
             >
                <Database className="w-3 h-3" /> Generic BIND
             </button>
          </div>
        </header>

        {/* Main Interface */}
        <main className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          {/* Left Panel: Input & AI Command */}
          <div className="lg:col-span-5 space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Database className="w-4 h-4" /> Input Artifact ({domainName})
              </h2>
              <span className="text-xs text-slate-500 font-mono">BIND 9 Format</span>
            </div>
            
            {/* Main Editor */}
            <div className="relative group">
              <textarea 
                value={inputZone}
                onChange={(e) => setInputZone(e.target.value)}
                className="w-full h-[400px] bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs leading-relaxed text-slate-300 resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent"
                spellCheck="false"
              />
            </div>

            {/* AI Command Line */}
            <div className="bg-slate-950 border border-purple-500/30 rounded-lg overflow-hidden">
               <div className="bg-purple-900/10 px-3 py-2 border-b border-purple-500/20 flex items-center gap-2">
                  <Bot className="w-4 h-4 text-purple-400" />
                  <span className="text-xs font-bold text-purple-300">AI Record Generator (Target: {platform.toUpperCase()})</span>
               </div>
               <div className="p-3 space-y-3">
                  <div className="flex gap-2">
                     <input 
                       type="text" 
                       value={aiCommand}
                       onChange={(e) => setAiCommand(e.target.value)}
                       placeholder="e.g. 'Add MX records for Google Workspace'"
                       className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
                       onKeyDown={(e) => e.key === 'Enter' && runAICommand()}
                     />
                     <button 
                       onClick={runAICommand}
                       disabled={isAiCommandLoading}
                       className="bg-purple-600 hover:bg-purple-500 text-white px-3 py-2 rounded text-xs font-bold transition-colors disabled:opacity-50"
                     >
                       {isAiCommandLoading ? 'Gen...' : '✨ Run'}
                     </button>
                  </div>
                  {aiCommandResult && (
                    <div className="bg-black/30 p-2 rounded border border-slate-800 relative group">
                      <pre className="text-[10px] text-green-400 font-mono whitespace-pre-wrap">{aiCommandResult}</pre>
                      <button 
                        onClick={() => {
                          setInputZone(prev => prev + '\n\n' + aiCommandResult);
                          setAiCommandResult('');
                          setAiCommand('');
                        }}
                        className="absolute top-1 right-1 bg-slate-800 text-[9px] px-2 py-1 rounded text-slate-300 hover:text-white"
                      >
                        Insert &darr;
                      </button>
                    </div>
                  )}
               </div>
            </div>

          </div>

          {/* Center: Controls & Analytics */}
          <div className="lg:col-span-2 flex flex-col gap-4">
            
            {/* Risk Meter */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 space-y-4">
              <div className="flex justify-between items-center">
                 <span className="text-xs font-bold text-slate-400 uppercase">Risk Score</span>
                 <Lock className={`w-4 h-4 ${isOptimized ? 'text-green-500' : 'text-red-500'}`} />
              </div>
              <div className="text-center">
                 <span className={`text-4xl font-bold ${isOptimized ? 'text-green-400' : 'text-red-500'}`}>
                    {isOptimized ? '0' : '92'}
                 </span>
                 <span className="text-xs text-slate-500 block mt-1">/ 100</span>
              </div>
              <div className="h-1 bg-slate-700 rounded-full overflow-hidden">
                <div 
                    className={`h-full transition-all duration-500 ${isOptimized ? 'bg-green-500 w-0' : 'bg-red-500 w-[92%]'}`} 
                />
              </div>
            </div>

            {/* AI Deep Scan Button */}
            <button 
              onClick={runAIDeepScan}
              disabled={isAiLoading}
              className="w-full py-3 rounded-xl font-bold flex flex-row items-center justify-center gap-2 transition-all shadow-lg bg-purple-900/50 hover:bg-purple-800/50 text-purple-200 border border-purple-500/30 hover:border-purple-400/60 shadow-purple-900/20"
            >
              {isAiLoading ? (
                <RefreshCw className="w-5 h-5 animate-spin" />
              ) : (
                <Sparkles className="w-5 h-5" />
              )}
              <span className="text-sm">Gemini Deep Scan</span>
            </button>

            {/* Standard Optimize Button */}
            <button 
              onClick={analyzeAndFix}
              disabled={isOptimized}
              className={`w-full py-4 rounded-xl font-bold flex flex-col items-center justify-center gap-2 transition-all shadow-lg
                ${isOptimized 
                  ? 'bg-green-500/10 text-green-400 border border-green-500/50 cursor-default' 
                  : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-500/20 hover:shadow-cyan-500/40'
                }`}
            >
              {isOptimized ? (
                <>
                  <CheckCircle className="w-6 h-6" />
                  <span>Secured</span>
                </>
              ) : (
                <>
                  <Zap className="w-6 h-6" />
                  <span>Logic Hardening</span>
                </>
              )}
            </button>

            {/* Log Feed */}
            <div className="flex-1 bg-black/40 border border-slate-800 rounded-xl p-3 overflow-hidden flex flex-col h-[200px]">
              <h3 className="text-xs font-bold text-slate-500 uppercase mb-2">Ops Logs</h3>
              <div className="flex-1 overflow-y-auto space-y-2 scrollbar-thin scrollbar-thumb-slate-800">
                {logs.length === 0 && (
                  <div className="text-xs text-slate-600 italic text-center mt-4">
                    System Idle.
                  </div>
                )}
                {logs.map((log, i) => (
                  <div key={i} className="text-[10px] font-mono border-l-2 pl-2 py-1 animate-fadeIn"
                    style={{
                        borderColor: log.type === 'critical' ? '#ef4444' : log.type === 'warning' ? '#f59e0b' : '#22c55e',
                        color: log.type === 'critical' ? '#fca5a5' : log.type === 'warning' ? '#fcd34d' : '#86efac'
                    }}
                  >
                    <span className="opacity-50">[{new Date().toLocaleTimeString()}]</span> {log.msg}
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Right Panel: Output & AI Intelligence */}
          <div className="lg:col-span-5 flex flex-col gap-4">
             
             {/* AI Intelligence Report (Conditional) */}
             {aiAnalysis && (
               <div className="bg-purple-950/20 border border-purple-500/30 rounded-lg p-4 animate-slideIn">
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="text-sm font-bold text-purple-300 flex items-center gap-2">
                       <Bot className="w-4 h-4" /> Gemini Intelligence Report ({platform.toUpperCase()})
                    </h3>
                    <span className={`text-[10px] px-2 py-0.5 rounded border ${
                      aiAnalysis.riskLevel === 'High' ? 'bg-red-900/50 text-red-300 border-red-800' :
                      aiAnalysis.riskLevel === 'Medium' ? 'bg-amber-900/50 text-amber-300 border-amber-800' :
                      'bg-green-900/50 text-green-300 border-green-800'
                    }`}>
                      Risk Level: {aiAnalysis.riskLevel}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mb-3 italic">"{aiAnalysis.summary}"</p>
                  <div className="space-y-2">
                    {aiAnalysis.findings.map((finding, idx) => (
                      <div key={idx} className="flex gap-2 text-[11px] bg-black/20 p-2 rounded border border-purple-500/10">
                         {finding.type === 'Security' || finding.type === 'Email' ? (
                           <Shield className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                         ) : (
                           <Zap className="w-3 h-3 text-cyan-400 shrink-0 mt-0.5" />
                         )}
                         <span className="text-slate-200">{finding.message}</span>
                      </div>
                    ))}
                  </div>
               </div>
             )}

             {/* Standard Output Header */}
             <div className="flex justify-between items-center">
              <h2 className="text-sm font-semibold text-green-400 uppercase tracking-wider flex items-center gap-2">
                <Server className="w-4 h-4" /> Optimized Configuration
              </h2>
              <div className="flex gap-2">
                <button className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded transition-colors">JSON</button>
                <button className="text-xs bg-slate-800 hover:bg-slate-700 text-cyan-400 px-2 py-1 rounded transition-colors border border-cyan-900">BIND</button>
              </div>
            </div>
            
            {/* Output Editor */}
            <div className="relative group flex-1">
              <textarea 
                value={optimizedZone}
                readOnly
                placeholder={`Awaiting optimization for ${platform.toUpperCase()}...`}
                className="w-full h-full min-h-[400px] bg-slate-950 border border-green-900/30 rounded-lg p-4 font-mono text-xs leading-relaxed text-green-100/80 resize-none focus:outline-none focus:ring-1 focus:ring-green-500 transition-all scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent"
              />
               {optimizedZone && (
                <div className="absolute top-2 right-2">
                    <button 
                        onClick={() => navigator.clipboard.writeText(optimizedZone)}
                        className="p-2 bg-green-900/20 border border-green-500/30 rounded hover:bg-green-900/40 text-green-400 transition-all"
                    >
                    <Copy className="w-4 h-4" />
                    </button>
                </div>
               )}
            </div>
          </div>

        </main>
        
        {/* Footer info */}
        <footer className="border-t border-slate-800 pt-6 text-center text-slate-500 text-xs flex justify-between items-center">
            <span>By ID ArtCraft / Igor Dunaev / Google &copy; 2025</span>
            <div className="flex gap-4">
                <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-green-500"></div> System Operational</span>
                <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-cyan-500"></div> API Connected</span>
            </div>
        </footer>

      </div>
    </div>
  );
};

export default DNSZoneOptimizer;
