"use client";

import React, { useState, useEffect } from 'react';
import { Shield, Activity, Network, Cpu, Lock, ChevronRight, CheckCircle, AlertTriangle, Zap, Server, RefreshCw } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

export default function AERISWebsite() {
  const [benchmarks15, setBenchmarks15] = useState<any>(null);
  const [benchmarks16, setBenchmarks16] = useState<any>(null);

  useEffect(() => {
    fetch('http://127.0.0.1:8000/api/benchmarks/step15').then(r => r.json()).then(setBenchmarks15).catch(() => {});
    fetch('http://127.0.0.1:8000/api/benchmarks/step16').then(r => r.json()).then(setBenchmarks16).catch(() => {});
  }, []);

  const scrollToDemo = () => {
    document.getElementById('live-demo')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-slate-200 font-sans selection:bg-indigo-500/30">
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 bg-[#09090b]/80 backdrop-blur-md border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="w-6 h-6 text-indigo-500" />
            <span className="font-bold text-white tracking-tight">AERIS-PQ6G</span>
          </div>
          <div className="hidden md:flex items-center space-x-8 text-sm font-medium text-slate-400">
            <a href="#how-it-works" className="hover:text-white transition-colors">How It Works</a>
            <a href="#architecture" className="hover:text-white transition-colors">Architecture</a>
            <a href="#validation" className="hover:text-white transition-colors">Validation</a>
          </div>
          <button onClick={scrollToDemo} className="bg-white text-black px-4 py-2 rounded-full text-sm font-medium hover:bg-slate-200 transition-colors">
            Try Live Demo
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-indigo-600/20 blur-[120px] rounded-full pointer-events-none" />
        <div className="max-w-7xl mx-auto px-6 relative z-10 text-center">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
            <div className="inline-flex items-center space-x-2 bg-white/5 border border-white/10 rounded-full px-3 py-1 mb-8">
              <span className="flex w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs font-medium text-slate-300">System Frozen & Validated</span>
            </div>
            <h1 className="text-5xl md:text-7xl font-bold text-white tracking-tight leading-tight mb-6">
              Adaptive Security for the <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">
                Post-Quantum Network Era
              </span>
            </h1>
            <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-10">
              Continuously evaluate network risk and dynamically orchestrate classical, post-quantum and hybrid security.
            </p>
            <div className="flex items-center justify-center space-x-4">
              <button onClick={scrollToDemo} className="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-3 rounded-full font-medium transition-all flex items-center space-x-2">
                <span>Launch Live Demo</span>
                <ChevronRight className="w-4 h-4" />
              </button>
              <a href="#validation" className="bg-white/5 hover:bg-white/10 text-white px-8 py-3 rounded-full font-medium border border-white/10 transition-all">
                Explore Validation
              </a>
            </div>
          </motion.div>

          {/* Hero Visual */}
          <motion.div 
            initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, delay: 0.2 }}
            className="mt-20 max-w-4xl mx-auto border border-white/10 rounded-2xl bg-black/50 backdrop-blur-sm overflow-hidden"
          >
            <div className="h-12 border-b border-white/10 flex items-center px-4 space-x-2 bg-white/5">
              <div className="w-3 h-3 rounded-full bg-rose-500/50" />
              <div className="w-3 h-3 rounded-full bg-amber-500/50" />
              <div className="w-3 h-3 rounded-full bg-emerald-500/50" />
            </div>
            <div className="p-8">
               <div className="flex flex-col md:flex-row items-center justify-center space-y-8 md:space-y-0 md:space-x-12">
                 <HeroNode title="NETWORK" icon={<Network />} active />
                 <ChevronRight className="w-6 h-6 text-slate-600" />
                 <HeroNode title="RISK" icon={<Activity />} active />
                 <ChevronRight className="w-6 h-6 text-slate-600" />
                 <HeroNode title="INTELLIGENCE" icon={<Cpu />} active />
                 <ChevronRight className="w-6 h-6 text-slate-600" />
                 <HeroNode title="DECISION" icon={<Shield />} active className="border-indigo-500 text-indigo-400 shadow-[0_0_30px_-5px_rgba(99,102,241,0.4)]" />
               </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Interactive Demo Section */}
      <section id="live-demo" className="py-24 bg-black relative border-y border-white/5">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-white mb-4">Try AERIS-PQ6G</h2>
            <p className="text-slate-400">Configure your scenario and watch the adaptive security engine respond.</p>
          </div>
          
          <LiveDemo />

        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="py-24 bg-[#09090b]">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="text-3xl font-bold text-white mb-16 text-center">How It Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <StepCard num="01" title="OBSERVE" desc="Understand the simulated security context continuously." icon={<Network />} />
            <StepCard num="02" title="ASSESS" desc="Evaluate security risk using rule-based and ML-assisted estimation." icon={<Activity />} />
            <StepCard num="03" title="DECIDE" desc="Determine the appropriate security posture dynamically." icon={<Cpu />} />
            <StepCard num="04" title="ADAPT" desc="Transition security mode when required to mitigate threats." icon={<Shield />} />
          </div>
        </div>
      </section>

      {/* Validation & Benchmarks */}
      <section id="validation" className="py-24 bg-[#0c0c10] border-t border-white/5">
        <div className="max-w-7xl mx-auto px-6">
          <div className="mb-16">
            <h2 className="text-3xl font-bold text-white mb-4">Research & Validation</h2>
            <p className="text-slate-400">Verified through automated experiments and stress matrices.</p>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-16">
            <StatCard val="233" label="Regression Tests" />
            <StatCard val="60" label="Scalability Configs" />
            <StatCard val="48" label="Automated Runs" />
            <StatCard val="33" label="Stress Matrices" />
            <StatCard val="4" label="Security Modes" />
            <StatCard val="5" label="Attack Categories" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="border border-white/10 rounded-2xl p-6 bg-black">
              <h3 className="text-lg font-medium text-white mb-6">Execution Time Scalability (Step 16)</h3>
              <div className="h-64">
                {benchmarks16 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={benchmarks16.slice(0, 5)}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                      <XAxis dataKey="devices" stroke="#888" tick={{fill: '#888'}} axisLine={false} />
                      <YAxis stroke="#888" tick={{fill: '#888'}} axisLine={false} tickFormatter={(val) => `${val}s`} />
                      <RechartsTooltip contentStyle={{backgroundColor: '#09090b', border: '1px solid #333', borderRadius: '8px'}} />
                      <Line type="monotone" dataKey="execution_time_sec" stroke="#6366f1" strokeWidth={3} dot={{r: 4, fill: '#6366f1'}} />
                    </LineChart>
                  </ResponsiveContainer>
                ) : <div className="flex items-center justify-center h-full text-slate-500">Loading benchmark data...</div>}
              </div>
            </div>

            <div className="border border-white/10 rounded-2xl p-6 bg-black">
              <h3 className="text-lg font-medium text-white mb-6">Capabilities</h3>
              <div className="space-y-4">
                <CapRow title="Post-Quantum Ready" desc="ML-KEM-768, ML-DSA-65 integrated" />
                <CapRow title="Hybrid Security" desc="Classical + PQC mechanisms fused" />
                <CapRow title="Risk-Aware Security" desc="Continuous simulated risk evaluation" />
                <CapRow title="Adaptive Orchestration" desc="Policy-driven security transitions" />
                <CapRow title="Controlled Threat Simulation" desc="Repeatable attack scenarios" />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-white/5 bg-black text-center text-slate-500">
         <p>AERIS-PQ6G • Adaptive Security Infrastructure for Next-Generation Networks</p>
         <p className="text-sm mt-2">Simulated research framework.</p>
      </footer>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* LIVE DEMO COMPONENT                                                        */
/* -------------------------------------------------------------------------- */

function LiveDemo() {
  // Inputs
  const [networkSize, setNetworkSize] = useState('500');
  const [securityMode, setSecurityMode] = useState('ADAPTIVE');
  const [targetDevice, setTargetDevice] = useState('Device 42');
  const [threatType, setThreatType] = useState('REPLAY_ATTACK');
  const [intensity, setIntensity] = useState('HIGH');

  // State
  const [status, setStatus] = useState<'IDLE' | 'LOADING' | 'DONE' | 'ERROR'>('IDLE');
  const [loadingStep, setLoadingStep] = useState(0);
  const [result, setResult] = useState<any>(null);

  const presets = [
    { label: "Normal Network", threat: "NO_ATTACK", int: "LOW", mode: "ADAPTIVE" },
    { label: "Replay Attack", threat: "REPLAY_ATTACK", int: "HIGH", mode: "ADAPTIVE" },
    { label: "Session Abuse", threat: "SESSION_ABUSE_ATTACK", int: "MEDIUM", mode: "HYBRID" },
  ];

  const applyPreset = (p: any) => {
    setThreatType(p.threat);
    setIntensity(p.int);
    setSecurityMode(p.mode);
  };

  const runSimulation = async () => {
    setStatus('LOADING');
    setLoadingStep(0);
    setResult(null);

    // Fake loading steps for cinematic effect
    const steps = [
      "INITIALIZING",
      "BUILDING NETWORK",
      "EVALUATING SECURITY CONTEXT",
      "CALCULATING RISK",
      "RUNNING SECURITY POLICY",
      "FINALIZING RESULT"
    ];

    for (let i = 0; i < steps.length; i++) {
      setLoadingStep(i);
      await new Promise(r => setTimeout(r, 400));
    }

    try {
      const res = await fetch('http://127.0.0.1:8000/api/run_demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          network_size: networkSize,
          security_mode: securityMode,
          target_device: targetDevice,
          attack_type: threatType, 
          intensity 
        })
      });
      if(!res.ok) throw new Error("Backend simulation failed");
      const data = await res.json();
      setResult(data);
      setStatus('DONE');
    } catch (e) {
      console.error(e);
      setStatus('ERROR');
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
      {/* Sidebar Controls */}
      <div className="lg:col-span-4 space-y-6">
        <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
          <h3 className="text-white font-medium mb-4 flex items-center justify-between">
            <span>Configure Scenario</span>
            <span className="text-xs text-indigo-400 bg-indigo-400/10 px-2 py-1 rounded">Interactive</span>
          </h3>
          
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider">Presets</label>
              <div className="flex flex-wrap gap-2">
                {presets.map(p => (
                  <button key={p.label} onClick={() => applyPreset(p)} className="text-xs bg-white/5 hover:bg-white/10 border border-white/10 rounded px-2 py-1 text-slate-300 transition-colors">
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-2 border-t border-white/10">
              <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider">Network Size</label>
              <select value={networkSize} onChange={e => setNetworkSize(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-2.5 text-sm text-white focus:border-indigo-500 outline-none">
                <option value="50">50 Devices</option>
                <option value="100">100 Devices</option>
                <option value="500">500 Devices</option>
                <option value="1000">1000 Devices</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider">Security Strategy</label>
              <select value={securityMode} onChange={e => setSecurityMode(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-2.5 text-sm text-white focus:border-indigo-500 outline-none">
                <option value="CLASSICAL">Classical</option>
                <option value="PQC">PQC</option>
                <option value="HYBRID">Hybrid</option>
                <option value="ADAPTIVE">Adaptive</option>
              </select>
              {securityMode === 'ADAPTIVE' && (
                <div className="text-xs text-slate-500 mt-2">Automatically selects the security mode based on evaluated risk.</div>
              )}
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider">Target Device</label>
              <input type="text" value={targetDevice} onChange={e => setTargetDevice(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-2.5 text-sm text-white focus:border-indigo-500 outline-none" />
            </div>

            <div className="pt-2 border-t border-white/10">
              <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider">Threat Scenario</label>
              <select value={threatType} onChange={e => setThreatType(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-2.5 text-sm text-white focus:border-indigo-500 outline-none">
                <option value="NO_ATTACK">No Threat</option>
                <option value="AUTHENTICATION_ATTACK">Authentication Attack</option>
                <option value="REPLAY_ATTACK">Replay Attack</option>
                <option value="MESSAGE_TAMPERING_ATTACK">Message Tampering Attack</option>
                <option value="SESSION_ABUSE_ATTACK">Session Abuse Attack</option>
                <option value="RESOURCE_PRESSURE_ATTACK">Resource Pressure Attack</option>
              </select>
            </div>

            {threatType !== 'NO_ATTACK' && (
              <div>
                <label className="block text-xs text-slate-400 mb-1 uppercase tracking-wider">Intensity</label>
                <select value={intensity} onChange={e => setIntensity(e.target.value)} className="w-full bg-black border border-white/10 rounded-lg p-2.5 text-sm text-white focus:border-indigo-500 outline-none">
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                </select>
              </div>
            )}
          </div>

          <div className="mt-6 pt-6 border-t border-white/10 flex space-x-3">
            <button 
              onClick={runSimulation} 
              disabled={status === 'LOADING'}
              className="flex-1 bg-white text-black hover:bg-slate-200 font-medium py-3 rounded-lg transition-colors flex justify-center items-center space-x-2 disabled:opacity-50"
            >
              {status === 'LOADING' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              <span>{status === 'LOADING' ? 'Simulating...' : 'Run Simulation'}</span>
            </button>
            {status === 'DONE' && (
              <button onClick={() => setStatus('IDLE')} className="p-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-slate-400 transition-colors" title="Reset Demo">
                <RefreshCw className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main View Area */}
      <div className="lg:col-span-8">
        <div className="h-full min-h-[600px] border border-white/10 rounded-2xl bg-[#0c0c10] overflow-hidden flex flex-col relative">
          
          {/* Header */}
          <div className="h-12 border-b border-white/10 bg-white/5 flex items-center px-4 justify-between">
            <div className="text-sm font-medium text-slate-400">Simulation Environment</div>
            <div className="flex space-x-2">
               <div className={`w-2 h-2 rounded-full ${status === 'LOADING' ? 'bg-amber-500 animate-pulse' : status === 'DONE' ? 'bg-emerald-500' : 'bg-slate-600'}`} />
            </div>
          </div>

          {/* Content Area */}
          <div className="flex-1 p-8 relative overflow-hidden flex items-center justify-center">
            
            <AnimatePresence mode="wait">
              
              {/* IDLE STATE */}
              {status === 'IDLE' && (
                <motion.div key="idle" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} className="text-center text-slate-500">
                  <Network className="w-16 h-16 mx-auto mb-4 opacity-20" />
                  <h3 className="text-xl text-white mb-2">Ready to Simulate</h3>
                  <p className="max-w-md mx-auto">Select a configuration on the left and click Run Simulation to evaluate the AERIS-PQ6G adaptive security engine.</p>
                </motion.div>
              )}

              {/* LOADING STATE */}
              {status === 'LOADING' && (
                <motion.div key="loading" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} className="w-full max-w-md">
                  <div className="space-y-4">
                    {["INITIALIZING", "BUILDING NETWORK", "EVALUATING SECURITY CONTEXT", "CALCULATING RISK", "RUNNING SECURITY POLICY", "FINALIZING RESULT"].map((step, idx) => (
                      <div key={step} className="flex items-center justify-between">
                        <span className={`text-sm font-mono ${loadingStep >= idx ? 'text-white' : 'text-slate-600'}`}>{step}</span>
                        {loadingStep > idx ? <CheckCircle className="w-4 h-4 text-emerald-500" /> : loadingStep === idx ? <RefreshCw className="w-4 h-4 text-indigo-400 animate-spin" /> : <div className="w-4 h-4" />}
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}

              {/* ERROR STATE */}
              {status === 'ERROR' && (
                <motion.div key="error" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} className="text-center text-rose-500">
                  <AlertTriangle className="w-16 h-16 mx-auto mb-4 opacity-50" />
                  <h3 className="text-xl text-white mb-2">Simulation Failed</h3>
                  <p>The backend simulation engine could not process this request.</p>
                </motion.div>
              )}

              {/* DONE STATE */}
              {status === 'DONE' && result && (
                <motion.div key="done" initial={{opacity:0, scale:0.95}} animate={{opacity:1, scale:1}} className="w-full h-full flex flex-col">
                  
                  {/* Top Status Bar */}
                  <div className="flex items-center justify-between mb-8 pb-4 border-b border-white/5">
                    <div>
                      <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Target</div>
                      <div className="text-lg text-white font-mono">{result.demo_context.target_device}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Network Base</div>
                      <div className="text-lg text-white">{result.demo_context.network_size} Devices</div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Overall Status</div>
                      <div className="text-lg text-white font-bold flex items-center justify-end space-x-2">
                        <Activity className="w-5 h-5 text-indigo-400" /> <span>SIMULATION COMPLETE</span>
                      </div>
                    </div>
                  </div>

                  {/* 3-Column Result Layout */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 flex-1">
                    
                    {/* Col 1: Threat Profile */}
                    <div className="bg-white/5 rounded-xl p-6 border border-white/5">
                      <div className="flex items-center space-x-2 mb-6">
                        <AlertTriangle className="w-5 h-5 text-rose-400" />
                        <h4 className="text-white font-medium">Threat Simulation</h4>
                      </div>
                      <div className="space-y-4">
                        <div>
                          <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Scenario</div>
                          <div className="text-sm text-white font-mono">{result.attack_type.replace(/_/g, ' ')}</div>
                        </div>
                        <div>
                          <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Intensity</div>
                          <div className="text-sm text-white">{result.intensity}</div>
                        </div>
                        <div className="pt-4 border-t border-white/5">
                          <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Attack Activity</div>
                          <div className="text-2xl text-rose-400 font-mono mb-1">
                            {result.metrics.attack_injections} <span className="text-sm text-slate-400 font-sans">attempts</span>
                          </div>
                          <div className="text-sm text-slate-300">
                             {result.response.replay_failures > 0 ? result.response.replay_failures : result.response.authentication_failures} security responses
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Col 2: Risk Assessment */}
                    <div className="bg-white/5 rounded-xl p-6 border border-white/5 relative overflow-hidden">
                      <div className="absolute top-0 right-0 w-32 h-32 bg-amber-500/10 blur-3xl -mr-10 -mt-10" />
                      <div className="flex items-center space-x-2 mb-6 relative">
                        <Activity className="w-5 h-5 text-amber-400" />
                        <h4 className="text-white font-medium">Risk Evaluation</h4>
                      </div>
                      
                      <div className="flex flex-col items-center justify-center py-4 relative">
                        <div className="w-32 h-32 rounded-full border-4 border-amber-500/20 flex flex-col items-center justify-center mb-6">
                          <span className="text-3xl font-bold text-white">{result.post_state.rule_risk_score.toFixed(1)}</span>
                          <span className="text-xs text-amber-400 font-bold">{result.post_state.rule_risk_level}</span>
                        </div>
                        
                        <div className="w-full space-y-2">
                          <div className="flex justify-between text-xs">
                            <span className="text-slate-400">Rule Risk</span>
                            <span className="text-white">{result.post_state.rule_risk_score.toFixed(2)}</span>
                          </div>
                          <div className="flex justify-between text-xs">
                            <span className="text-slate-400">ML Risk</span>
                            <span className="text-white">{result.post_state.ml_risk_score.toFixed(2)}</span>
                          </div>
                          <div className="flex justify-between text-xs pt-2 border-t border-white/5">
                            <span className="text-slate-400">Risk Delta</span>
                            <span className="text-white font-mono">{result.metrics.risk_delta > 0 ? '+' : ''}{result.metrics.risk_delta.toFixed(2)}</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Col 3: Adaptive Decision */}
                    <div className="bg-gradient-to-b from-indigo-500/10 to-transparent rounded-xl p-6 border border-indigo-500/20">
                      <div className="flex items-center space-x-2 mb-6">
                        <Cpu className="w-5 h-5 text-indigo-400" />
                        <h4 className="text-white font-medium">Adaptive Decision</h4>
                      </div>

                      <div className="mb-6 pb-6 border-b border-white/5">
                        <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Selected Strategy</div>
                        <div className="text-sm text-indigo-300 font-bold">{result.demo_context.security_mode}</div>
                      </div>

                      {result.response.mode_changed ? (
                        <div className="space-y-6">
                          <div className="text-center p-3 bg-black/40 rounded-lg border border-white/5">
                            <div className="text-xs text-slate-500 mb-1">BEFORE</div>
                            <div className="text-sm text-slate-300 font-mono">{result.response.transition_source_mode}</div>
                          </div>
                          
                          <div className="flex justify-center">
                            <div className="h-8 w-px bg-indigo-500/50 relative">
                              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-[#0c0c10] p-1 rounded-full border border-indigo-500/30">
                                <ChevronRight className="w-3 h-3 text-indigo-400 rotate-90" />
                              </div>
                            </div>
                          </div>

                          <div className="text-center p-4 bg-indigo-500/20 rounded-lg border border-indigo-500/50 shadow-[0_0_20px_-5px_rgba(99,102,241,0.3)]">
                            <div className="text-xs text-indigo-300 mb-1">ADAPTED TO</div>
                            <div className="text-lg text-white font-bold font-mono">{result.response.transition_target_mode}</div>
                          </div>
                          
                          <div className="text-center text-xs text-slate-400">
                            Latency: {result.response.transition_latency_ticks} ticks
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-4 pt-2">
                          <div>
                            <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Current Mode</div>
                            <div className="text-sm text-white font-mono">{result.post_state.security_mode}</div>
                          </div>
                          <div>
                            <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Target Mode</div>
                            <div className="text-sm text-white font-mono">{result.post_state.security_mode}</div>
                          </div>
                          <div className="pt-4 border-t border-white/5">
                            <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Transition</div>
                            <div className="text-sm text-white">None</div>
                          </div>
                          <div className="pt-4 border-t border-white/5">
                            <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider">Security Context</div>
                            <div className="text-sm text-slate-400">No escalation required</div>
                          </div>
                        </div>
                      )}
                    </div>

                  </div>
                </motion.div>
              )}

            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* UI HELPERS                                                                 */
/* -------------------------------------------------------------------------- */

function HeroNode({ title, icon, active, className="" }: any) {
  return (
    <div className={`flex flex-col items-center p-4 rounded-xl border ${active ? 'bg-white/5 border-white/20' : 'border-white/5'} ${className}`}>
      <div className={`mb-3 ${active ? 'text-white' : 'text-slate-500'}`}>{icon}</div>
      <div className="text-xs font-semibold tracking-wider">{title}</div>
    </div>
  );
}

function StepCard({ num, title, desc, icon }: any) {
  return (
    <div className="p-6 rounded-2xl bg-white/5 border border-white/10 hover:bg-white/10 transition-colors">
      <div className="text-indigo-500 mb-6">{icon}</div>
      <div className="text-sm font-bold text-slate-500 mb-2">{num}</div>
      <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
      <p className="text-sm text-slate-400 leading-relaxed">{desc}</p>
    </div>
  );
}

function StatCard({ val, label }: any) {
  return (
    <div className="p-4 rounded-xl bg-white/5 border border-white/10 text-center">
      <div className="text-2xl font-bold text-white mb-1">{val}</div>
      <div className="text-xs text-slate-400 uppercase tracking-wider">{label}</div>
    </div>
  );
}

function CapRow({ title, desc }: any) {
  return (
    <div className="flex items-start space-x-3 p-3 rounded-lg hover:bg-white/5 transition-colors">
      <CheckCircle className="w-5 h-5 text-indigo-500 shrink-0 mt-0.5" />
      <div>
        <div className="text-sm font-medium text-white">{title}</div>
        <div className="text-xs text-slate-400 mt-1">{desc}</div>
      </div>
    </div>
  );
}
