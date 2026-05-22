const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const DATA_FILE = path.join(__dirname, 'data', 'threats.json');
let threats = [];
try {
  threats = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
} catch (e) {
  threats = [];
}

// simple SSE clients list
const clients = new Set();
let simInterval = null;
const simulatedSamples = [
  {
    srcIP: '198.51.100.50', dstIP: '10.0.0.5', proto: 'UDP', port: 80,
    prediction: 'DDoS', risk: 'CRITICAL', confidence: 96, dataset: 'RT_IOT2022',
    features: { packet_rate: 2000, bwd_bytes_mean: 0, active_mean: 0.0005 }
  },
  {
    srcIP: '203.0.113.88', dstIP: '10.0.0.9', proto: 'TCP', port: 22,
    prediction: 'Brute Force', risk: 'HIGH', confidence: 89, dataset: 'LYCOS-IDS2017',
    features: { packet_rate: 400, bwd_bytes_mean: 1, active_mean: 0.01 }
  },
  {
    srcIP: '192.0.2.10', dstIP: '10.0.0.2', proto: 'TCP', port: 8080,
    prediction: 'PortScan', risk: 'HIGH', confidence: 92, dataset: 'LYCOS-IDS2017',
    features: { packet_rate: 600, bwd_bytes_mean: 0, active_mean: 0.005 }
  }
];

function persist() {
  try {
    fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(threats, null, 2));
  } catch (e) { console.error('persist error', e); }
}

// GET all threats
app.get('/api/threats', (req, res) => {
  res.json(threats.slice(0, 500));
});

// single threat
app.get('/api/threats/:id', (req, res) => {
  const t = threats.find(x => String(x.id) === String(req.params.id));
  if (!t) return res.status(404).json({ error: 'not found' });
  res.json(t);
});

// SSE stream for live events
app.get('/api/stream', (req, res) => {
  res.writeHead(200, {
    Connection: 'keep-alive',
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache'
  });
  res.write('\n');

  const client = res;
  clients.add(client);

  req.on('close', () => {
    clients.delete(client);
  });
});

// start simulation (server will emit events)
app.post('/api/simulate', (req, res) => {
  if (simInterval) return res.status(400).json({ message: 'already running' });
  let counter = 0;
  const startTime = Date.now();
  simInterval = setInterval(() => {
    const sample = simulatedSamples[counter % simulatedSamples.length];
    const item = {
      id: Date.now() + Math.floor(Math.random() * 1000),
      time: new Date().toISOString().replace('T', ' ').slice(0, 19),
      srcIP: sample.srcIP,
      dstIP: sample.dstIP,
      proto: sample.proto,
      port: sample.port,
      prediction: sample.prediction,
      risk: sample.risk,
      confidence: sample.confidence,
      dataset: sample.dataset,
      features: sample.features
    };
    threats.unshift(item);
    threats = threats.slice(0, 500);
    persist();

    // push to all SSE clients
    const payload = `data: ${JSON.stringify(item)}\n\n`;
    clients.forEach(c => {
      try { c.write(payload); } catch (e) { /* ignore */ }
    });

    counter += 1;
    if (counter >= 60) {
      clearInterval(simInterval);
      simInterval = null;
    }
  }, 500);
  res.json({ message: 'simulation started' });
});

// stop simulation
app.post('/api/stop', (req, res) => {
  if (simInterval) {
    clearInterval(simInterval);
    simInterval = null;
    return res.json({ message: 'stopped' });
  }
  res.json({ message: 'not running' });
});

app.post('/api/threat/run-pipeline', async (req, res) => {
  try {
    // If you want this endpoint to also start live simulation, reuse existing simulate logic
    // For now we build a pipeline response from current threats array (loaded earlier)
    const metrics = {
      detected_threats_last_1h: threats.length,
      high_critical_alerts: threats.filter(t => t.risk === 'HIGH' || t.risk === 'CRITICAL').length,
      benign_flows: threats.filter(t => String(t.prediction).toLowerCase().includes('benign')).length,
    };

    const model = {
      name: 'RandomForest',
      ok: true,
      last_retrain: '2025-11-20',
      overall_accuracy: 0.94,
      macro_f1: 0.92,
      dataset_summary: { lycos_flows: 30000, rt_iot_flows: 15000 },
    };

    // simple timeline generation from last N threats (aggregate per minute)
    const timelineMap = new Map();
    (threats || []).slice(0, 200).forEach(t => {
      const timeKey = (t.time || new Date().toISOString()).slice(0,16); // minute precision
      if (!timelineMap.has(timeKey)) timelineMap.set(timeKey, { time: timeKey, low:0, medium:0, high:0, critical:0, benign:0, malicious:0 });
      const entry = timelineMap.get(timeKey);
      const rk = (t.risk || 'LOW').toUpperCase();
      if (rk === 'CRITICAL') entry.critical += 1;
      else if (rk === 'HIGH') entry.high += 1;
      else if (rk === 'MEDIUM') entry.medium += 1;
      else entry.low += 1;
      const isMal = !String(t.prediction || '').toLowerCase().includes('benign');
      if (isMal) entry.malicious += 1; else entry.benign += 1;
    });
    const live_threat_series = Array.from(timelineMap.values()).slice(-60);
    const anomaly_series = live_threat_series.map(x => ({ time: x.time, benign: x.benign, malicious: x.malicious }));

    // Build response object
    const response = {
      metrics,
      model,
      timeline: {
        anomaly_series,
        live_threat_series,
      },
      threats: threats.slice(0, 200),
    };

    // Optionally start simulation if query param ?simulate=true or body.simulate
    if (req.query.simulate === 'true' || (req.body && req.body.simulate)) {
      // reuse simulate logic if exists
      if (!simInterval) {
        // trigger existing simulate code by calling the same function or route
        // simple approach: call existing simulate endpoint internally
        // (this will push SSE events as before)
        // NOTE: keep this non-blocking
        setTimeout(() => {
          // attempt internal request to /api/simulate
          try {
            const http = require('http');
            const options = { method: 'POST', port: process.env.PORT || 4001, path: '/api/simulate', headers: { 'Content-Type': 'application/json' } };
            const r = http.request(options);
            r.on('error', ()=>{});
            r.end();
          } catch (e) {}
        }, 50);
      }
    }

    return res.json(response);
  } catch (err) {
    console.error('run-pipeline error', err);
    return res.status(500).json({ error: 'pipeline error' });
  }
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => console.log(`AI Threat backend running on http://localhost:${PORT}`));