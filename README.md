<h1>AEGIS // Modular Host XDR & Active Defense Platform</h1>

<p>
  <b>Status:</b> Early MVP (Proof-of-Concept) <br>
  <b>Platform:</b> Windows 10 / 11 (x64) <br>
  <b>Stack:</b> Python 3 (asyncio / psutil / sqlite3), Vanilla JS, Cyberpunk HUD
</p>

<hr>

<h2>Overview</h2>

<p>
AEGIS is an open-source, lightweight host-level Extended Detection and Response (XDR) and active deception framework. It consolidates behavioral process heuristics, ransomware decoy monitoring, network socket telemetry, and hardware-level USB enforcement into a single unified local security engine with an interactive web-based HUD.
</p>

<blockquote>
  <b>MVP Notice:</b> This project is currently in the <b>Minimum Viable Product (MVP)</b> stage. The core event bus, local HTTP dashboard, and telemetry hooks are functional, but active mitigation routines and UI data density are under active development.
</blockquote>

<hr>

<h2>Architecture & Core Modules (Integrated MVP)</h2>

<ul>
  <li><b>Process Guard:</b> Live process telemetry analysis, LOLBins execution detection, and threat scoring with dynamic decay mechanics.</li>
  <li><b>Canary Engine:</b> Strategically placed decoy files paired with real-time Shannon entropy analysis to intercept early-stage ransomware encryption.</li>
  <li><b>Peripheral Guard:</b> Windows PnP hardware interception, tracking USBSTOR registry artifacts and driver logs with automated isolation capabilities.</li>
  <li><b>Network Deception & IPS:</b> Low-interaction honeypot listeners that trigger instant remote IP blocks via Windows Defender Firewall.</li>
  <li><b>Telemetry & Topography:</b> Real-time TCP socket-to-PID mapping and local network subnet discovery.</li>
</ul>

<hr>

<h2>Quick Start</h2>

<h3>Prerequisites</h3>
<ul>
  <li>Windows 10 / 11 x64</li>
  <li>Python 3.10 or higher</li>
  <li><b>Administrator Privileges</b> (required for firewall modifications and PnP hardware drops)</li>
</ul>

<h3>Installation & Run</h3>

<pre><code>git clone https://github.com/d3fuse99/AEGIS.git
cd AEGIS
pip install -r requirements.txt
python aegis.py</code></pre>

<p>
Once running, access the local operations console at: <br>
<b>http://127.0.0.1:8080</b>
</p>

<hr>

<h2>Project Roadmap</h2>

<ul>
  <li>[x] Core MVP skeleton and asynchronous event bus.</li>
  <li>[x] Local HTTP server with modular HUD routing.</li>
  <li>[ ] Fix map tile rendering and switch to zero-dependency vector grid.</li>
  <li>[ ] Finalize kernel-level privilege elevation checks for automated process mitigation.</li>
  <li>[ ] Real-time SSE streaming for live forensic incident feeds.</li>
</ul>

<hr>

<h2>License</h2>

<p>
Distributed under the <b>MIT License</b>. Developed strictly for defensive security research and infrastructure hardening.
</p>
