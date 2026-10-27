let currentTab = 'overview';
let globalThreatScore = 0;
let totalMitigations = 0;
let mapInstance = null;
let activeConnections = [];
let audioCtx = null;

function initAudio() {
    if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
}

function playAlarmTone() {
    try {
        initAudio();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(440, audioCtx.currentTime);
        osc.frequency.linearRampToValueAtTime(880, audioCtx.currentTime + 0.3);
        gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.35);
    } catch (e) {}
}

function showToast(title, body) {
    const box = document.getElementById('toast-box');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<strong>${title}</strong><br>${body}`;
    box.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

function switchTab(tabId) {
    currentTab = tabId;
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    
    const target = document.getElementById(`tab-${tabId}`);
    if (target) target.classList.add('active');

    const labels = {
        overview: 'Threat Radar // Live Telemetry',
        processes: 'Process Guard // Memory & Heuristics',
        deception: 'Deception Ops // Canary & Trap Matrix',
        network: 'Network Topography // Sockets & GeoIP',
        lan: 'LAN Discovery // Asset & Intruder Auditor',
        usb: 'Hardware Access Control // Peripheral Lockdown'
    };
    document.getElementById('page-title').textContent = labels[tabId] || 'Command Panel';

    if (tabId === 'network') {
        setTimeout(initMap, 200);
    }
}

function initMap() {
    if (mapInstance) {
        mapInstance.invalidateSize();
        return;
    }
    const mapEl = document.getElementById('map-container');
    if (!mapEl) return;
    mapInstance = L.map(mapEl).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; CARTO'
    }).addTo(mapInstance);
}

function appendEventLog(event) {
    const feed = document.getElementById('event-feed');
    if (!feed) return;
    const row = document.createElement('div');
    row.className = 'log-row';
    const ts = new Date().toTimeString().split(' ')[0];
    row.innerHTML = `<span class="log-ts">[${ts}]</span> <span style="color:var(--accent-cyan)">[${event.source || 'CORE'}]</span> <span>${event.description || event.type || ''}</span>`;
    feed.insertBefore(row, feed.firstChild);
    if (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

function handleIncomingEvent(ev) {
    appendEventLog(ev);

    if (ev.type === 'PROCESS_SUSPICIOUS') {
        renderProcessRow(ev.data);
    } else if (ev.type === 'CANARY_BREACH') {
        playAlarmTone();
        showToast('CRITICAL BREACH', `Ransomware Canary touched: ${ev.data.decoy}`);
    } else if (ev.type === 'HONEYPOT_ATTACK') {
        playAlarmTone();
        showToast('HONEYPOT HIT', `Attacker IP ${ev.data.ip} probed port ${ev.data.port}`);
    } else if (ev.type === 'MITIGATION_EXECUTED') {
        totalMitigations++;
        document.getElementById('mitigation-count').textContent = totalMitigations;
        showToast('THREAT NEUTRALIZED', `PID ${ev.data.pid} (${ev.data.name}) killed`);
    }
}

function renderProcessRow(data) {
    const tbody = document.getElementById('process-table-body');
    if (!tbody) return;
    let row = document.getElementById(`proc-${data.pid}`);
    if (!row) {
        row = document.createElement('tr');
        row.id = `proc-${data.pid}`;
        tbody.prepend(row);
    }
    const badge = data.score >= 75 ? 'badge-crit' : (data.score >= 40 ? 'badge-warn' : 'badge-safe');
    row.innerHTML = `
        <td>${data.pid}</td>
        <td><strong>${data.name}</strong></td>
        <td>${data.score || 0}</td>
        <td><span class="badge ${badge}">${data.score >= 75 ? 'CRITICAL' : 'SUSPICIOUS'}</span></td>
        <td>${data.heuristic || 'ANOMALY'}</td>
        <td>
            <button class="btn btn-danger" onclick="killProcess(${data.pid})">Kill</button>
            <button class="btn" onclick="whitelistProcess('${data.name}')">Trust</button>
        </td>
    `;
}

async function killProcess(pid) {
    await fetch('/api/process/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
    });
}

async function whitelistProcess(name) {
    await fetch('/api/process/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    });
}

function initSSE() {
    const source = new EventSource('/api/events');
    source.onmessage = (e) => {
        try {
            const parsed = JSON.parse(e.data);
            if (parsed.type) handleIncomingEvent(parsed);
        } catch (err) {}
    };
}

async function fetchInitialData() {
    try {
        const res = await fetch('/api/recent_events');
        const data = await res.json();
        data.forEach(item => appendEventLog(item));
    } catch (e) {}
}

window.addEventListener('DOMContentLoaded', () => {
    initSSE();
    fetchInitialData();
});