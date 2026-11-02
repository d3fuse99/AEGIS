let currentTab = 'procs';
let isPaused = false;
let processInventory = [];
let processRowMap = new Map();

const bootEntries = [
    { text: "aegis-core active telemetry engine initialized.", level: "info" },
    { text: "VirtualQueryEx RWX memory scanner attached.", level: "dim" },
    { text: "Canary anti-ransomware trap vectors armed.", level: "info" },
    { text: "Honeypot perimeter listeners bound.", level: "dim" },
    { text: "PnP hardware lockdown active.", level: "info" }
];

function pulseBeacon() {
    const beacon = document.getElementById('beacon-node');
    if (!beacon) return;
    beacon.classList.remove('flash');
    void beacon.offsetWidth;
    beacon.classList.add('flash');
}

function writeAuditEntry(text, level = "info") {
    if (isPaused) return;
    const feed = document.getElementById('diagnostic-feed');
    if (!feed) return;
    const line = document.createElement('div');
    line.className = 'log-row ' + level;
    const time = new Date().toTimeString().split(' ')[0];
    line.textContent = `[${time}] ${text}`;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
}

function updateClockTicker() {
    const clock = document.getElementById('time-ticker');
    if (clock) {
        clock.textContent = `[${new Date().toTimeString().split(' ')[0]}]`;
    }
}

function toggleFeedPause() {
    isPaused = !isPaused;
    const btn = document.getElementById('btn-toggle-pause');
    if (btn) {
        btn.textContent = isPaused ? "[RESUME FEED]" : "[PAUSE FEED]";
        btn.classList.toggle('active-pause', isPaused);
    }
    writeAuditEntry(isPaused ? "Audit telemetry feed suspended by analyst." : "Audit telemetry feed resumed.", "dim");
}

function triggerDumpExport() {
    writeAuditEntry("Extracting database audit dump...", "dim");
    window.open('/api/export_dump');
}

function handleFilterKey(e) {
    applyProcessFilter();
}

window.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement.id !== 'cli-filter-input') {
        e.preventDefault();
        const input = document.getElementById('cli-filter-input');
        if (input) {
            input.focus();
            input.select();
        }
    }
});

function switchTab(name) {
    currentTab = name;
    document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

    const view = document.getElementById(`tab-view-${name}`);
    const btn = document.getElementById(`tab-btn-${name}`);
    if (view) view.classList.add('active');
    if (btn) btn.classList.add('active');

    if (name === 'usb') {
        fetchUsbRegistry();
    }
}

function formatScoreBar(score) {
    if (!score || score <= 0) {
        return `<span style="color:#333333;">—</span>`;
    }
    const blocks = Math.min(10, Math.ceil(score / 10));
    const bar = '■'.repeat(blocks) + '□'.repeat(10 - blocks);
    const cssClass = score >= 60 ? 'score-bar-high' : 'score-bar-med';
    return `<span class="${cssClass}">[${bar}] ${score}</span>`;
}

async function fetchSnapshot() {
    try {
        const res = await fetch('/api/snapshot');
        if (!res.ok) return;
        const snap = await res.json();

        pulseBeacon();

        const daemonLbl = document.getElementById('lbl-daemon-pid');
        if (daemonLbl) daemonLbl.textContent = snap.daemon_pid || "----";

        const adminLbl = document.getElementById('lbl-admin-status');
        if (adminLbl) {
            adminLbl.textContent = snap.is_admin ? "ELEVATED" : "LIMITED";
            adminLbl.style.color = snap.is_admin ? "#00ff66" : "#ffaa00";
        }

        const honeypotMetric = document.getElementById('metric-honeypot-count');
        if (honeypotMetric && snap.bound_honeypot_ports) {
            honeypotMetric.textContent = `${snap.bound_honeypot_ports.length} BOUND`;
        }

        document.getElementById('metric-quarantine-count').textContent = snap.quarantine_count;
        document.getElementById('metric-blocked-ips').textContent = snap.blocked_count;

        processInventory = snap.processes || [];
        applyProcessFilter();
    } catch (e) {}
}

function applyProcessFilter() {
    const input = document.getElementById('cli-filter-input');
    const query = input ? input.value.trim().toLowerCase() : "";
    const tbody = document.getElementById('tbody-processes');
    if (!tbody) return;

    const filtered = processInventory.filter(p => {
        if (!query) return true;
        return p.name.toLowerCase().includes(query) || 
               String(p.pid).includes(query) || 
               (p.exe && p.exe.toLowerCase().includes(query)) ||
               (p.remote_socket && p.remote_socket.toLowerCase().includes(query));
    });

    const activePids = new Set(filtered.map(p => p.pid));

    for (const [pid, tr] of processRowMap.entries()) {
        if (!activePids.has(pid)) {
            tr.remove();
            processRowMap.delete(pid);
        }
    }

    filtered.forEach(p => {
        let tr = processRowMap.get(p.pid);
        const scoreHtml = formatScoreBar(p.score || 0);
        const netBadge = p.remote_socket 
            ? `<span class="net-tag" title="Connected: ${p.remote_socket}">[NET: ${p.remote_socket}]</span>` 
            : '';

        if (!tr) {
            tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="col-pid">${p.pid}</td>
                <td class="col-name" style="color:#ffffff; font-weight:bold;">${p.name} ${netBadge}</td>
                <td class="col-score">${scoreHtml}</td>
                <td class="col-path" style="color:#444444; max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${p.exe}">${p.exe || 'SYSTEM'}</td>
                <td class="col-actions">
                    <button class="btn-kill" onclick="killPid(${p.pid})">KILL</button>
                    <button class="btn-trust" onclick="trustProcessName('${p.name}')">TRUST</button>
                </td>
            `;
            tbody.appendChild(tr);
            processRowMap.set(p.pid, tr);
        } else {
            const scoreCol = tr.querySelector('.col-score');
            if (scoreCol && scoreCol.innerHTML !== scoreHtml) {
                scoreCol.innerHTML = scoreHtml;
            }
            const nameCol = tr.querySelector('.col-name');
            const targetNameHtml = `${p.name} ${netBadge}`;
            if (nameCol && nameCol.innerHTML !== targetNameHtml) {
                nameCol.innerHTML = targetNameHtml;
            }
        }

        if ((p.score || 0) >= 70) {
            tr.classList.add('strobe-alert');
        } else {
            tr.classList.remove('strobe-alert');
        }
    });
}

async function killPid(pid) {
    writeAuditEntry(`Signal sent: Suspend, isolate & kill PID ${pid}`, "warn");
    await fetch('/api/process/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pid })
    });
    fetchSnapshot();
}

async function trustProcessName(name) {
    await fetch('/api/process/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name })
    });
    writeAuditEntry(`Policy update: Whitelisted binary [${name}]`, "info");
    fetchSnapshot();
}

async function fetchUsbRegistry() {
    try {
        const res = await fetch('/api/usb_list');
        if (!res.ok) return;
        const list = await res.json();
        const tbody = document.getElementById('tbody-usb');
        if (!tbody) return;
        tbody.innerHTML = '';

        list.forEach(dev => {
            const tr = document.createElement('tr');
            const state = dev.is_whitelisted 
                ? '<span style="color:#00ff66">APPROVED</span>' 
                : '<span style="color:#ff2244">DROP_BLOCK</span>';
            const action = dev.is_whitelisted
                ? `<button class="btn-kill" onclick="updateUsbWhitelist('${dev.serial}', false)">REVOKE</button>`
                : `<button class="btn-trust" onclick="updateUsbWhitelist('${dev.serial}', true)">ALLOW</button>`;

            tr.innerHTML = `
                <td style="color:#00e5ff">${dev.serial}</td>
                <td style="color:#ffffff">${dev.name}</td>
                <td>${dev.first_connected || 'Unknown'}</td>
                <td>${state}</td>
                <td>${action}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

async function updateUsbWhitelist(serial, allow) {
    const url = allow ? '/api/usb/whitelist/add' : '/api/usb/whitelist/remove';
    await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serial: serial })
    });
    fetchUsbRegistry();
}

function initSSEBridge() {
    const sse = new EventSource('/api/events');
    sse.onmessage = (e) => {
        try {
            const ev = JSON.parse(e.data);
            if (!ev.type) return;

            if (ev.type === "CANARY_BREACH") {
                writeAuditEntry(`CRITICAL: Ransomware modification on [${ev.data.decoy}] (Entropy: ${ev.data.entropy})`, "alert");
                writeAuditEntry(`MITIGATION: Terminated offending process PID ${ev.data.pid}`, "alert");
                fetchSnapshot();
            } else if (ev.type === "HONEYPOT_ATTACK") {
                writeAuditEntry(`TRAP INTRUSION: Port ${ev.data.port} (${ev.data.service}) hit by ${ev.data.ip}`, "alert");
                writeAuditEntry(`PAYLOAD: ${ev.data.payload}`, "warn");
            } else if (ev.type === "PROCESS_SUSPICIOUS") {
                writeAuditEntry(`ANOMALY: PID ${ev.data.pid} [${ev.data.name}] -> Heuristic: ${ev.data.heuristic}`, "warn");
            } else if (ev.type === "MITIGATION_EXECUTED") {
                writeAuditEntry(`CONTAINMENT: PID ${ev.data.pid} destroyed and locked in quarantine.`, "info");
                fetchSnapshot();
            }
        } catch (err) {}
    };
}

function playBootSequence() {
    let delay = 0;
    bootEntries.forEach((item, idx) => {
        setTimeout(() => {
            writeAuditEntry(item.text, item.level);
            if (idx === bootEntries.length - 1) {
                fetchSnapshot();
                initSSEBridge();
            }
        }, delay);
        delay += 60;
    });
}

window.addEventListener('DOMContentLoaded', () => {
    playBootSequence();
    setInterval(updateClockTicker, 1000);
    setInterval(fetchSnapshot, 2500);
});