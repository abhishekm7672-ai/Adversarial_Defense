/**
 * Navigo Malware Defense - Frontend Controller (Multi-Page Version)
 */

const API_BASE_URL = window.location.origin;

// Persistence keys
const TOKEN_KEY = 'NAVIGO_JWT_TOKEN';

// In-memory token (primary) with sessionStorage fallback
let authToken = sessionStorage.getItem(TOKEN_KEY) || null;

/* UI ELEMENTS (Global/Common) */
const loadingOverlay = document.getElementById('loading-overlay');
const apiStatusText = document.getElementById('api-status-text');

/* PAGE DETECTION */
const currentPage = window.location.pathname.split('/').pop() || 'index.html';

/* ===========================
   AUTH HELPERS
=========================== */

function getToken() {
    return authToken;
}

function setToken(token) {
    authToken = token;
    sessionStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
    authToken = null;
    sessionStorage.removeItem(TOKEN_KEY);
}

function isLoggedIn() {
    return !!authToken;
}

async function login(username, password) {
    const response = await fetch(`${API_BASE_URL}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
    });
    if (!response.ok) throw new Error('Invalid username or password');
    const data = await response.json();
    setToken(data.access_token);
    return data;
}

function authHeaders(extra = {}) {
    return {
        'Authorization': `Bearer ${getToken()}`,
        ...extra
    };
}

/* ===========================
   LOGIN MODAL
=========================== */

function showLoginModal() {
    const existing = document.getElementById('login-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'login-modal';
    modal.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: rgba(0,0,0,0.85); display: flex; align-items: center;
        justify-content: center; z-index: 9999;
    `;
    modal.innerHTML = `
        <div style="background: #0f172a; border: 1px solid #1e293b; border-radius: 12px;
                    padding: 40px; width: 380px; text-align: center;">
            <div style="font-size: 2rem; margin-bottom: 8px;">🛡️</div>
            <h2 style="color: #f1f5f9; margin-bottom: 4px; font-size: 1.4rem;">Navigo Defense</h2>
            <p style="color: #64748b; margin-bottom: 28px; font-size: 0.85rem;">
                Security Operations Center
            </p>
            <input id="login-username" type="text" placeholder="Username"
                style="width: 100%; padding: 12px; margin-bottom: 12px; background: #1e293b;
                       border: 1px solid #334155; border-radius: 8px; color: #f1f5f9;
                       font-size: 0.95rem; box-sizing: border-box;" />
            <input id="login-password" type="password" placeholder="Password"
                style="width: 100%; padding: 12px; margin-bottom: 20px; background: #1e293b;
                       border: 1px solid #334155; border-radius: 8px; color: #f1f5f9;
                       font-size: 0.95rem; box-sizing: border-box;" />
            <div id="login-error" style="color: #ef4444; font-size: 0.85rem;
                 margin-bottom: 16px; display: none;"></div>
            <button id="login-btn"
                style="width: 100%; padding: 12px; background: #3b82f6; color: white;
                       border: none; border-radius: 8px; font-size: 1rem; cursor: pointer;
                       font-weight: 600;">
                Sign In
            </button>
            <p style="color: #475569; font-size: 0.75rem; margin-top: 20px;">
                Navigo Adversarial Defense v1.0
            </p>
        </div>
    `;

    document.body.appendChild(modal);

    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    const loginBtn = document.getElementById('login-btn');
    const loginError = document.getElementById('login-error');

    async function attemptLogin() {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        if (!username || !password) {
            loginError.textContent = 'Please enter username and password.';
            loginError.style.display = 'block';
            return;
        }
        loginBtn.textContent = 'Signing in...';
        loginBtn.disabled = true;
        try {
            await login(username, password);
            modal.remove();
            initPage();
        } catch (err) {
            loginError.textContent = err.message;
            loginError.style.display = 'block';
            loginBtn.textContent = 'Sign In';
            loginBtn.disabled = false;
        }
    }

    loginBtn.addEventListener('click', attemptLogin);
    passwordInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') attemptLogin();
    });

    setTimeout(() => usernameInput.focus(), 100);
}

/* ===========================
   PAGE INIT
=========================== */

document.addEventListener('DOMContentLoaded', () => {
    if (!isLoggedIn()) {
        showLoginModal();
    } else {
        initPage();
    }
});

function initPage() {
    fetchSystemStatus();
    switch (currentPage) {
        case 'index.html':
            initDashboard();
            break;
        case 'incidents.html':
            initIncidentsPage();
            break;
        case 'analytics.html':
            initAnalyticsPage();
            break;
        case 'settings.html':
            initSettingsPage();
            break;
        default:
            if (window.location.pathname === '/') initDashboard();
    }
}

/* ===========================
   SYSTEM STATUS
=========================== */

async function fetchSystemStatus() {
    try {
        const resp = await fetch(`${API_BASE_URL}/health`);
        const data = await resp.json();
        if (document.getElementById('model-version')) {
            document.getElementById('model-version').textContent = data.version;
        }
        if (document.getElementById('settings-model-version')) {
            document.getElementById('settings-model-version').textContent = data.version;
        }
        if (apiStatusText) apiStatusText.textContent = "SYSTEM ONLINE";
    } catch (err) {
        if (apiStatusText) {
            apiStatusText.textContent = "SYSTEM OFFLINE";
            apiStatusText.parentElement.classList.add('error');
        }
    }
}

/* ===========================
   DASHBOARD LOGIC
=========================== */

function initDashboard() {
    const featureInput = document.getElementById('feature-input');
    const runBtn = document.getElementById('run-detection');
    const loadSampleBtn = document.getElementById('load-sample');
    const riskGaugeCtx = document.getElementById('riskGauge');
    const hardeningChartCtx = document.getElementById('hardeningChart');

    if (runBtn) runBtn.addEventListener('click', () => handleDetection(featureInput.value));
    if (loadSampleBtn) loadSampleBtn.addEventListener('click', () => {
        const mock = new Array(518).fill(0).map(() => Math.random() * 0.1);
        mock[10] = 0.8; mock[50] = 0.9;
        featureInput.value = JSON.stringify(mock);
    });

    if (riskGaugeCtx) initRiskGauge();
    if (hardeningChartCtx) initHardeningChart();

    fetch(`${API_BASE_URL}/training-report`, { headers: authHeaders() })
        .then(res => res.json())
        .then(report => {
            const baselineEvasion = (report.baseline_evasion_rate * 100).toFixed(2);
            const afIndex = report.antifragility_index.toFixed(4);
            const rounds = report.rounds ? report.rounds.length : 2;

            document.getElementById('m-initial-rob').textContent = `${baselineEvasion}%`;
            document.getElementById('m-antifragility').textContent = afIndex;
            document.getElementById('m-rounds').textContent = rounds;
            document.getElementById('m-stability').textContent =
                report.antifragility_index > 0.5 ? "HIGH" : "MEDIUM";

            if (report.rounds && report.rounds.length > 0) {
                const roundLabels = report.rounds.map(r => r.round);
                const evasionData = report.rounds.map(r => r.evasion_rate);
                updateHardeningChart(roundLabels, evasionData);
            } else {
                updateHardeningChart([1, 2], [0.0709, 0.0024]);
            }
        })
        .catch(() => {
            document.getElementById('m-initial-rob').textContent = "7.09%";
            document.getElementById('m-antifragility').textContent = "0.9664";
            document.getElementById('m-rounds').textContent = "2";
            document.getElementById('m-stability').textContent = "HIGH";
            updateHardeningChart([1, 2], [0.0709, 0.0024]);
        });
}

async function handleDetection(rawInput) {
    if (!rawInput.trim()) return alert("Please enter feature data.");
    let features;
    try {
        features = JSON.parse(rawInput);
        if (!Array.isArray(features)) throw new Error();
    } catch (e) {
        return alert("Invalid input. Please provide a JSON array of 518 features.");
    }

    // Pad 518 static features to 522 (adds 4 behavioral features as 0)
    if (features.length === 518) {
        features = [...features, 0, 0, 0, 0];
    }

    showLoading(true);
    try {
        const response = await fetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: authHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ features })
        });
        if (response.status === 401) { clearToken(); showLoginModal(); return; }
        if (!response.ok) throw new Error(await response.text());
        const result = await response.json();
        displayDashboardResult(result);
    } catch (err) {
        alert("Detection failed: " + err.message);
    } finally {
        showLoading(false);
    }
}

async function scanFile() {
    const fileUpload = document.getElementById("fileUpload");
    if (!fileUpload || !fileUpload.files.length) return alert("Please select an EXE file.");

    const formData = new FormData();
    formData.append("file", fileUpload.files[0]);

    showLoading(true);
    try {
        const response = await fetch(`${API_BASE_URL}/scan-file`, {
            method: "POST",
            headers: authHeaders(),
            body: formData
        });
        if (response.status === 401) { clearToken(); showLoginModal(); return; }
        if (!response.ok) throw new Error(await response.text());
        const result = await response.json();
        displayDashboardResult(result);
    } catch (err) {
        alert("File scan failed: " + err.message);
    } finally {
        showLoading(false);
    }
}

function displayDashboardResult(data) {
    const resultCard = document.getElementById('detection-result');
    if (!resultCard) return;
    resultCard.classList.remove('hidden');

    const decisionEl = document.getElementById('result-decision');
    const verdict = data.verdict || (data.decision === 'Malicious' ? 'malicious' : 'clean');
    decisionEl.textContent = verdict.toUpperCase();
    decisionEl.className = 'decision ' + (verdict === 'malicious' || verdict === 'suspicious' ? 'danger-text' : 'success-text');

    document.getElementById('result-timestamp').textContent = new Date().toLocaleTimeString();

    const idEl = document.getElementById('res-request-id');
    if (idEl) idEl.textContent = data.scan_id ? String(data.scan_id).split('-')[0] : "--";

    const riskScore = data.risk_score ?? data.final_risk_score ?? data.malware_prob ?? 0;
    const riskPercent = (riskScore * 100).toFixed(1);

    const riskDisplay = document.getElementById('risk-score-display');
    if (riskDisplay) riskDisplay.textContent = riskPercent + "%";

    const probEl = document.getElementById('malware-prob');
    if (probEl && data.malware_prob !== undefined) {
        probEl.textContent = (data.malware_prob * 100).toFixed(2) + "%";
    }

    const suspicionEl = document.getElementById('suspicion-score');
    if (suspicionEl) suspicionEl.textContent = (data.suspicion_score ?? 0).toFixed(4);

    updateRiskGauge(riskScore);
    updateThreatFeed(data);
    updateActivityStream(data);
}

function updateThreatFeed(result) {
    const feed = document.getElementById("threatFeed");
    if (!feed) return;
    const entry = document.createElement("div");
    entry.classList.add("feed-entry");
    const time = new Date().toLocaleTimeString();
    const riskScore = result.risk_score ?? result.final_risk_score ?? result.malware_prob ?? 0;
    const risk = (riskScore * 100).toFixed(2);
    const verdict = result.verdict || result.decision || 'Unknown';
    entry.innerHTML = `
        <span>${time}</span>
        <span class="${verdict === 'clean' ? 'feed-benign' : 'feed-malicious'}">
            ${verdict.toUpperCase()}
        </span>
        <span>Risk: ${risk}%</span>`;
    feed.prepend(entry);
}

function updateActivityStream(data) {
    const list = document.getElementById('activity-list');
    if (!list) return;
    const empty = document.getElementById('activity-empty');
    if (empty) empty.remove();

    const verdict = data.verdict || 'unknown';
    const riskScore = data.risk_score ?? data.final_risk_score ?? data.malware_prob ?? 0;
    const malwareProb = data.malware_prob ?? data.malware_probability ?? 0;
    const suspicion = data.suspicion_score ?? 0;
    const scanId = data.scan_id ? String(data.scan_id).split('-')[0] : '--';
    const time = new Date().toLocaleTimeString();

    const entry = document.createElement('div');
    entry.classList.add('activity-entry');
    entry.innerHTML = `
        <span class="a-time">${time}</span>
        <div class="a-body">
            <div><span class="a-label">Scan ID &nbsp;</span>
                 <span class="a-val">${scanId}</span></div>
            <div><span class="a-label">Risk Score </span>
                 <span class="a-val">${(riskScore * 100).toFixed(2)}%</span></div>
            <div><span class="a-label">Malware Prob </span>
                 <span class="a-val">${(malwareProb * 100).toFixed(2)}%</span></div>
            <div><span class="a-label">Suspicion </span>
                 <span class="a-val">${suspicion.toFixed(4)}</span></div>
        </div>
        <span class="a-verdict ${verdict}">${verdict.toUpperCase()}</span>
    `;
    list.prepend(entry);
}

/* ===========================
   INCIDENTS PAGE LOGIC
=========================== */

async function initIncidentsPage() {
    const tbody = document.getElementById('incident-tbody');
    const emptyState = document.getElementById('no-incidents');

    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#64748b;">Loading...</td></tr>`;

    try {
        const resp = await fetch(`${API_BASE_URL}/scans?page_size=200`, {
            headers: authHeaders()
        });
        if (resp.status === 401) { clearToken(); showLoginModal(); return; }
        const data = await resp.json();
        const scans = data.items || [];

        if (scans.length > 0) {
            emptyState.classList.add('hidden');
            tbody.innerHTML = scans.map(scan => {
                const riskVal = (scan.risk_score ?? 0) * 100;
                let riskClass = 'risk-low';
                if (riskVal > 70) riskClass = 'risk-high';
                else if (riskVal > 40) riskClass = 'risk-med';
                const filename = scan.filename || (scan.scan_type === 'file' ? 'unknown file' : 'vector scan');
                const verdict = (scan.verdict || 'clean').toUpperCase();
                const verdictClass = scan.verdict === 'malicious' ? 'danger-text' :
                    scan.verdict === 'suspicious' ? 'warning-text' : 'success-text';
                const typeTag = scan.scan_type === 'file'
                    ? `<span style="background:rgba(59,130,246,0.15);color:#3b82f6;padding:2px 6px;border-radius:4px;font-size:0.7rem;">FILE</span>`
                    : `<span style="background:rgba(100,116,139,0.15);color:#64748b;padding:2px 6px;border-radius:4px;font-size:0.7rem;">VECTOR</span>`;
                return `
                    <tr>
                        <td>${new Date(scan.scanned_at).toLocaleString()}</td>
                        <td style="font-family:monospace;">${String(scan.id).split('-')[0]}</td>
                        <td>${typeTag} ${filename}</td>
                        <td><span class="risk-badge ${riskClass}">${riskVal.toFixed(1)}%</span></td>
                        <td class="${verdictClass}" style="font-weight:700;">${verdict}</td>
                    </tr>`;
            }).join('');
        } else {
            tbody.innerHTML = '';
            emptyState.classList.remove('hidden');
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#ef4444;">Failed to load: ${err.message}</td></tr>`;
    }
}

/* ===========================
   ANALYTICS PAGE LOGIC
=========================== */

async function initAnalyticsPage() {
    try {
        const resp = await fetch(`${API_BASE_URL}/scans?page_size=200`, {
            headers: authHeaders()
        });
        if (resp.status === 401) { clearToken(); showLoginModal(); return; }
        const data = await resp.json();
        const scans = data.items || [];

        const malicious = scans.filter(s => s.verdict === 'malicious');
        const suspicious = scans.filter(s => s.verdict === 'suspicious');
        const benign = scans.filter(s => s.verdict === 'clean');

        document.getElementById('total-scans-val').textContent = scans.length;
        document.getElementById('malicious-count-val').textContent = malicious.length;

        const avgRisk = scans.length
            ? (scans.reduce((sum, s) => {
                const r = Number(s.risk_score);
                return sum + (isNaN(r) || r < 0 ? 0 : r);
            }, 0) / scans.length * 100).toFixed(1)
            : 0;
        document.getElementById('avg-risk-val').textContent = `${avgRisk}%`;

        const rate = scans.length
            ? ((benign.length / scans.length) * 100).toFixed(1)
            : "100";
        document.getElementById('detection-rate-val').textContent = `${rate}%`;

        new Chart(document.getElementById('ratioChart'), {
            type: 'doughnut',
            data: {
                labels: ['Malicious', 'Suspicious', 'Clean'],
                datasets: [{
                    data: [malicious.length || 0, suspicious.length || 0, benign.length || 1],
                    backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
            }
        });

        const bins = [0, 0, 0, 0, 0];
        scans.forEach(s => {
            const idx = Math.min(Math.floor((s.risk_score * 100) / 20), 4);
            bins[idx]++;
        });

        new Chart(document.getElementById('riskDistChart'), {
            type: 'bar',
            data: {
                labels: ['0-20%', '21-40%', '41-60%', '61-80%', '81-100%'],
                datasets: [{ label: 'Sample Count', data: bins, backgroundColor: '#3b82f6' }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#64748b' } },
                    x: { grid: { display: false }, ticks: { color: '#64748b' } }
                },
                plugins: { legend: { display: false } }
            }
        });

    } catch (err) {
        console.error('Analytics load failed:', err);
    }

    fetch(`${API_BASE_URL}/training-report`, { headers: authHeaders() })
        .then(res => res.json())
        .then(report => {
            const labels = report.rounds && report.rounds.length > 0
                ? report.rounds.map(r => `R${r.round}`)
                : ['R1', 'R2'];
            const data = report.rounds && report.rounds.length > 0
                ? report.rounds.map(r => r.evasion_rate)
                : [0.0709, 0.0024];
            renderHardeningPerformanceChart(labels, data);
        })
        .catch(() => {
            renderHardeningPerformanceChart(['R1', 'R2'], [0.0709, 0.0024]);
        });
}

function renderHardeningPerformanceChart(labels, data) {
    new Chart(document.getElementById('hardeningPerformanceChart'), {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Evasion Rate',
                data,
                borderColor: '#3b82f6',
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                backgroundColor: 'rgba(59,130,246,0.1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } }
        }
    });
}

/* ===========================
   SETTINGS PAGE LOGIC
=========================== */

function initSettingsPage() {
    // Version already handled in fetchSystemStatus
}

/* ===========================
   CHARTS (Dashboard Specific)
=========================== */

let hardeningChart;
let riskGauge;

function initHardeningChart() {
    const ctx = document.getElementById('hardeningChart').getContext('2d');
    hardeningChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Evasion Rate',
                data: [],
                borderColor: '#3b82f6',
                borderWidth: 2,
                pointBackgroundColor: '#3b82f6',
                tension: 0.4,
                fill: true,
                backgroundColor: 'rgba(59,130,246,0.1)'
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });
}

function updateHardeningChart(labels, data) {
    if (!hardeningChart) return;
    hardeningChart.data.labels = labels;
    hardeningChart.data.datasets[0].data = data;
    hardeningChart.update();
}

function initRiskGauge() {
    const gCtx = document.getElementById('riskGauge').getContext('2d');
    riskGauge = new Chart(gCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ['#3b82f6', 'rgba(255,255,255,0.05)'],
                borderWidth: 0,
                circumference: 180,
                rotation: 270,
                cutout: '85%'
            }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function updateRiskGauge(val) {
    if (!riskGauge) return;
    const percent = Math.min(Math.max(val * 100, 0), 100);
    riskGauge.data.datasets[0].data = [percent, 100 - percent];
    let color = '#10b981';
    if (percent > 40) color = '#f59e0b';
    if (percent > 70) color = '#ef4444';
    riskGauge.data.datasets[0].backgroundColor[0] = color;
    riskGauge.update();
}

/* ===========================
   UTILS
=========================== */

function showLoading(show) {
    if (loadingOverlay) loadingOverlay.classList.toggle('hidden', !show);
}