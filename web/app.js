/*
 *   Aegis AV — Premium Client Engine
 *   Toast system, modal helpers, command palette, Chart.js integration,
 *   security score, and full controllers for every dashboard page.
 */

let socket = null;
let currentActivePage = 'dashboard';
let scanInterval = null;
let processSort = 'cpu';
let processTimer = null;
let charts = {};
let notifMuted = false;
let lastSecurityScore = null;

/* ───────────────────────────── Boot ───────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
    initTitleBar();
    initResize();
    initNavigation();
    initWebSocket();
    initCommandPalette();
    initKeyboardShortcuts();

    // First paint
    loadDashboardStats();
    loadSecurityScore();
    loadSettings();
    loadHistory();
    loadQuarantine();
    loadThreats();
    loadWhitelist();
    runOptimizerScan();
    updateNotifBadge();

    // Periodic refresh
    setInterval(loadDashboardStats, 6000);
    setInterval(loadSecurityScore, 15000);
    setInterval(updateNotifBadge, 12000);
});

/* ─────────────────── Page navigation ──────────────────── */
const PAGE_TITLES = {
    'dashboard':       ['Protection Hub', 'Live security score and real-time monitor feed'],
    'scanner':         ['Threat Scanner', 'Multi-engine on-demand scanning'],
    'threats':         ['Active Threats', 'Unresolved threats awaiting action'],
    'quarantine':      ['Isolation Vault', 'Encrypted, inert, and isolated storage'],
    'web-shield':      ['Web & Download Shield', 'URL reputation + download inspector'],
    'firewall':        ['Application Firewall', 'Outbound monitor & intrusion detection'],
    'ransomware':      ['Ransomware Shield', 'Behavior monitor for protected folders'],
    'vulnerabilities': ['System Vulnerabilities', 'Misconfigurations & missing updates'],
    'network':         ['Network Inspector', 'Live network connections & interfaces'],
    'processes':       ['Process Manager', 'Live processes with suspicious flagging'],
    'startup':         ['Startup Items', 'Programs running at Windows boot'],
    'optimizer':       ['Performance Optimizer', 'Clean junk, caches, and dead registry'],
    'reports':         ['Reports & Analytics', '14-day threat & scan history'],
    'threat-intel':    ['Threat Intelligence', 'Latest security advisories'],
    'schedules':       ['Scan Scheduler', 'Automated scans, daily / weekly / boot'],
    'password':        ['Password Health', 'Offline strength + breach check'],
    'whitelist':       ['Exclusion Rules', 'Whitelisted paths and hashes'],
    'history':         ['Scan History', 'Audit trail of every scan operation'],
    'settings':        ['Settings', 'Toggle defensive engines & engine config'],
};

function initNavigation() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTo(btn.getAttribute('data-target')));
    });
}

function switchTo(target) {
    if (!target || target === currentActivePage) return;
    document.querySelectorAll('.nav-btn').forEach(b => {
        b.classList.toggle('active', b.getAttribute('data-target') === target);
    });
    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === target);
    });
    currentActivePage = target;
    const meta = PAGE_TITLES[target] || ['Aegis AV', ''];
    document.getElementById('page-title').innerText = meta[0];
    document.getElementById('page-subtitle').innerText = meta[1];

    // Defer per-page loaders so the transition stays smooth
    setTimeout(() => triggerPageRefresh(target), 12);
}

function triggerPageRefresh(pageId) {
    const dispatch = {
        'dashboard':       () => { loadDashboardStats(); loadSecurityScore(); },
        'threats':         loadThreats,
        'quarantine':      loadQuarantine,
        'history':         loadHistory,
        'optimizer':       runOptimizerScan,
        'settings':        loadSettings,
        'whitelist':       loadWhitelist,
        'web-shield':      loadWebShield,
        'firewall':        loadFirewall,
        'ransomware':      loadRansomware,
        'vulnerabilities': () => loadVulnerabilities(false),
        'network':         loadNetwork,
        'processes':       () => startProcessLoop(),
        'startup':         loadStartup,
        'reports':         loadReports,
        'threat-intel':    loadThreatIntel,
        'schedules':       loadSchedules,
    };
    // Stop the process polling loop when leaving that page
    if (pageId !== 'processes' && processTimer) { clearInterval(processTimer); processTimer = null; }
    (dispatch[pageId] || (() => {}))();
}

/* ─────────────────── WebSocket ──────────────────── */
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        updateConnectionStatus(true);
    };
    socket.onmessage = (ev) => {
        try {
            const data = JSON.parse(ev.data);
            if (data.type === 'system_stats') handleSystemStats(data);
            else if (data.type === 'monitor_event') appendMonitorFeed(data.event);
            else if (data.type === 'scan_progress') updateScanProgress(data.status);
            else if (data.type === 'notification') handleIncomingNotification(data.notification);
            else if (data.type === 'download_alert') handleDownloadAlert(data.payload);
            else if (data.type === 'intrusion_alert') {
                appendMonitorFeed({
                    event_type: 'intrusion',
                    file_path: data.event.details,
                    timestamp: data.event.timestamp,
                });
            }
            else if (data.type === 'ransomware_alert') {
                appendMonitorFeed({
                    event_type: 'ransomware',
                    file_path: data.event.path || data.event.details,
                    timestamp: data.event.timestamp,
                });
            }
        } catch (e) { console.error(e); }
    };
    socket.onclose = () => {
        updateConnectionStatus(false);
        setTimeout(initWebSocket, 3000);
    };
}

function handleSystemStats(data) {
    const cpu = Math.round(data.cpu || 0);
    const ram = Math.round(data.ram || 0);
    document.getElementById('cpu-bar').style.width = `${cpu}%`;
    document.getElementById('cpu-lbl').innerText = `${cpu}%`;
    document.getElementById('ram-bar').style.width = `${ram}%`;
    document.getElementById('ram-lbl').innerText = `${ram}%`;

    if (data.net) {
        document.getElementById('net-up').innerText = `${data.net.up_kbs} KB/s`;
        document.getElementById('net-down').innerText = `${data.net.dn_kbs} KB/s`;
    }

    const hwPri = document.getElementById('hw-priority');
    hwPri.innerText = data.performance_mode ? 'HIGH PRIORITY' : 'STANDARD';
    hwPri.className = data.performance_mode ? 'alloc-val highlight' : 'alloc-val';
}

function updateConnectionStatus(connected) {
    const dot = document.getElementById('conn-dot');
    const title = document.getElementById('conn-title');
    const subtitle = document.getElementById('conn-subtitle');
    if (connected) {
        dot.className = 'conn-dot green';
        title.innerText = 'System Protected';
        subtitle.innerText = 'All engines online';
    } else {
        dot.className = 'conn-dot red';
        title.innerText = 'Engine Offline';
        subtitle.innerText = 'Reconnecting…';
    }
}

/* ─────────────────── Toast notifications ─────────────────── */
function toast({title, message='', severity='info', timeout=5000}) {
    if (notifMuted && severity !== 'critical') return; // game mode
    const stack = document.getElementById('toast-stack');
    const div = document.createElement('div');
    div.className = `toast ${severity}`;

    const icon = ({
        info: 'ℹ', success: '✓', warning: '⚠', critical: '⛔',
    })[severity] || 'ℹ';

    div.innerHTML = `
        <button class="toast-close">×</button>
        <h4><span class="toast-icon">${icon}</span> ${escapeHtml(title)}</h4>
        ${message ? `<p>${escapeHtml(message)}</p>` : ''}
        <div class="toast-progress" style="animation-duration:${timeout}ms"></div>
    `;
    stack.appendChild(div);
    requestAnimationFrame(() => div.classList.add('show'));

    const close = () => {
        div.classList.add('dismiss');
        setTimeout(() => div.remove(), 350);
    };
    div.querySelector('.toast-close').addEventListener('click', close);
    setTimeout(close, timeout);
}

function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[c]);
}

function handleIncomingNotification(n) {
    toast({
        title: n.title,
        message: n.message,
        severity: n.severity || 'info',
        timeout: n.severity === 'critical' ? 9000 : 5000,
    });
    updateNotifBadge();
}

function handleDownloadAlert(payload) {
    // The toast is already pushed by server via 'notification', this just feeds the WS log
    appendMonitorFeed({
        event_type: payload.verdict === 'malicious' ? 'threat' : 'download',
        file_path: payload.file_path,
        details: `Download ${payload.verdict}`,
        timestamp: payload.timestamp,
    });
}

/* ─────────────────── Modal system ─────────────────── */
function showModal({title, body='', confirmText='Confirm', cancelText='Cancel',
                    onConfirm=null, onCancel=null, danger=false}) {
    return new Promise((resolve) => {
        const root = document.getElementById('modal-root');
        const card = document.createElement('div');
        card.className = 'modal-card';
        card.innerHTML = `
            <h3>${escapeHtml(title)}</h3>
            ${typeof body === 'string' ? `<p>${body}</p>` : ''}
            <div class="modal-actions">
                <button class="btn btn-cancel" data-action="cancel">${escapeHtml(cancelText)}</button>
                <button class="btn ${danger ? 'btn-danger' : 'btn-accent'}" data-action="confirm">${escapeHtml(confirmText)}</button>
            </div>
        `;
        if (body instanceof HTMLElement) {
            card.insertBefore(body, card.querySelector('.modal-actions'));
        }
        root.innerHTML = '';
        root.appendChild(card);
        root.classList.add('show');

        const close = (val) => {
            root.classList.remove('show');
            root.innerHTML = '';
            resolve(val);
        };
        card.querySelector('[data-action="confirm"]').addEventListener('click', () => {
            if (onConfirm) onConfirm();
            close(true);
        });
        card.querySelector('[data-action="cancel"]').addEventListener('click', () => {
            if (onCancel) onCancel();
            close(false);
        });
    });
}

function showInputModal({title, body='', placeholder='', confirmText='OK', defaultValue=''}) {
    return new Promise((resolve) => {
        const root = document.getElementById('modal-root');
        const card = document.createElement('div');
        card.className = 'modal-card';
        card.innerHTML = `
            <h3>${escapeHtml(title)}</h3>
            ${body ? `<p>${escapeHtml(body)}</p>` : ''}
            <input type="text" class="premium-input modal-input" id="modal-input" placeholder="${escapeHtml(placeholder)}" value="${escapeHtml(defaultValue)}">
            <div class="modal-actions">
                <button class="btn btn-cancel" data-action="cancel">Cancel</button>
                <button class="btn btn-accent" data-action="confirm">${escapeHtml(confirmText)}</button>
            </div>
        `;
        root.innerHTML = '';
        root.appendChild(card);
        root.classList.add('show');

        const input = card.querySelector('#modal-input');
        setTimeout(() => input.focus(), 100);

        const close = (val) => {
            root.classList.remove('show');
            root.innerHTML = '';
            resolve(val);
        };
        const confirm = () => close(input.value);
        const cancel = () => close(null);
        card.querySelector('[data-action="confirm"]').addEventListener('click', confirm);
        card.querySelector('[data-action="cancel"]').addEventListener('click', cancel);
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') confirm();
            if (e.key === 'Escape') cancel();
        });
    });
}

/* ─────────────────── Command palette / search ─────────────────── */
const COMMANDS = [
    { label: 'Open Dashboard',          target: 'dashboard',       hint: 'Nav' },
    { label: 'Run Quick Scan',          action: () => startScan('quick'), hint: 'Scan' },
    { label: 'Run Full Scan',           action: () => startScan('full'),  hint: 'Scan' },
    { label: 'Open Scanner',            target: 'scanner',         hint: 'Nav' },
    { label: 'Open Threats',            target: 'threats',         hint: 'Nav' },
    { label: 'Open Quarantine',         target: 'quarantine',      hint: 'Nav' },
    { label: 'Open Web Shield',         target: 'web-shield',      hint: 'Nav' },
    { label: 'Open Firewall',           target: 'firewall',        hint: 'Nav' },
    { label: 'Open Ransomware Shield',  target: 'ransomware',      hint: 'Nav' },
    { label: 'Open Vulnerabilities',    target: 'vulnerabilities', hint: 'Nav' },
    { label: 'Open Network',            target: 'network',         hint: 'Nav' },
    { label: 'Open Processes',          target: 'processes',       hint: 'Nav' },
    { label: 'Open Startup Items',      target: 'startup',         hint: 'Nav' },
    { label: 'Open Optimizer',          target: 'optimizer',       hint: 'Nav' },
    { label: 'Open Reports',            target: 'reports',         hint: 'Nav' },
    { label: 'Open Threat Intel',       target: 'threat-intel',    hint: 'Nav' },
    { label: 'Open Scheduler',          target: 'schedules',       hint: 'Nav' },
    { label: 'Open Password Health',    target: 'password',        hint: 'Nav' },
    { label: 'Open Exclusions',         target: 'whitelist',       hint: 'Nav' },
    { label: 'Open Settings',           target: 'settings',        hint: 'Nav' },
    { label: 'Toggle Game Mode',        action: () => toggleGameMode(), hint: 'Action' },
    { label: 'Refresh Security Score',  action: () => loadSecurityScore(), hint: 'Action' },
];

function initCommandPalette() {
    const input = document.getElementById('cmd-input');
    const results = document.getElementById('cmd-results');
    let activeIdx = 0;

    const render = (filter) => {
        const f = (filter || '').toLowerCase();
        const list = COMMANDS.filter(c => c.label.toLowerCase().includes(f));
        results.innerHTML = list.map((c, i) => `
            <div class="cmd-row ${i === activeIdx ? 'active' : ''}" data-i="${i}">
                <span>${escapeHtml(c.label)}</span>
                <span class="cmd-hint">${escapeHtml(c.hint || '')}</span>
            </div>
        `).join('');
        Array.from(results.querySelectorAll('.cmd-row')).forEach(row => {
            row.addEventListener('click', () => execCommand(list[parseInt(row.dataset.i)]));
        });
        return list;
    };
    let currentList = render('');

    input.addEventListener('input', () => { activeIdx = 0; currentList = render(input.value); });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') return closeCommandPalette();
        if (e.key === 'ArrowDown') { e.preventDefault(); activeIdx = Math.min(activeIdx + 1, currentList.length - 1); currentList = render(input.value); }
        if (e.key === 'ArrowUp') { e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); currentList = render(input.value); }
        if (e.key === 'Enter') { e.preventDefault(); if (currentList[activeIdx]) execCommand(currentList[activeIdx]); }
    });

    document.querySelectorAll('[data-cmd-close]').forEach(el => el.addEventListener('click', closeCommandPalette));
}

function openCommandPalette() {
    const palette = document.getElementById('cmd-palette');
    palette.classList.add('show');
    setTimeout(() => document.getElementById('cmd-input').focus(), 50);
}
function closeCommandPalette() {
    const palette = document.getElementById('cmd-palette');
    palette.classList.remove('show');
    document.getElementById('cmd-input').value = '';
}

function execCommand(cmd) {
    if (!cmd) return;
    closeCommandPalette();
    if (cmd.target) switchTo(cmd.target);
    if (cmd.action) cmd.action();
}

function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            openCommandPalette();
        }
        if (e.key === 'Escape') {
            closeCommandPalette();
            const root = document.getElementById('modal-root');
            if (root.classList.contains('show')) root.classList.remove('show');
        }
    });
}

/* ─────────────────── Custom title bar (frameless window) ─────────────────── */
function initTitleBar() {
    const callApi = (name) => {
        const api = window.pywebview && window.pywebview.api;
        if (api && typeof api[name] === 'function') {
            try { return api[name](); } catch (e) { console.warn('pywebview api error', e); }
        }
    };

    const min   = document.getElementById('tb-min');
    const max   = document.getElementById('tb-max');
    const close = document.getElementById('tb-close');
    if (!min || !max || !close) return;

    min.addEventListener('click',  () => callApi('minimize'));
    max.addEventListener('click',  () => callApi('toggle_maximize'));
    close.addEventListener('click', () => callApi('close'));

    // Double-click the drag area toggles maximize
    const drag = document.querySelector('.tb-drag');
    if (drag) drag.addEventListener('dblclick', () => callApi('toggle_maximize'));
}

function initResize() {
    const right = document.querySelector('.resize-handle.right');
    const bottom = document.querySelector('.resize-handle.bottom');
    const bottomRight = document.querySelector('.resize-handle.bottom-right');

    let startX, startY, startWidth, startHeight;
    let activeHandle = null;

    const onMouseDown = (e, handleType) => {
        e.preventDefault();
        startX = e.clientX;
        startY = e.clientY;
        startWidth = window.outerWidth || window.innerWidth;
        startHeight = window.outerHeight || window.innerHeight;
        activeHandle = handleType;
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    };

    const onMouseMove = (e) => {
        if (!activeHandle) return;
        const deltaX = e.clientX - startX;
        const deltaY = e.clientY - startY;

        let newWidth = startWidth;
        let newHeight = startHeight;

        if (activeHandle === 'right' || activeHandle === 'bottomRight') {
            newWidth = Math.max(1024, startWidth + deltaX);
        }
        if (activeHandle === 'bottom' || activeHandle === 'bottomRight') {
            newHeight = Math.max(680, startHeight + deltaY);
        }

        const api = window.pywebview && window.pywebview.api;
        if (api && typeof api.resize === 'function') {
            api.resize(newWidth, newHeight);
        }
    };

    const onMouseUp = () => {
        activeHandle = null;
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    };

    if (right) right.addEventListener('mousedown', (e) => onMouseDown(e, 'right'));
    if (bottom) bottom.addEventListener('mousedown', (e) => onMouseDown(e, 'bottom'));
    if (bottomRight) bottomRight.addEventListener('mousedown', (e) => onMouseDown(e, 'bottomRight'));
}

/* ─────────────────── Monitor feed ─────────────────── */
function appendMonitorFeed(event) {
    const feed = document.getElementById('monitor-feed-list');
    if (!feed) return;
    const empty = feed.querySelector('.empty-feed');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = 'feed-item';

    let typeClass = 'write';
    let typeTag = 'FILE';
    const et = (event.event_type || '').toLowerCase();
    if (et.includes('process')) { typeClass = 'process'; typeTag = 'PROCESS'; }
    else if (et.includes('network') || et.includes('connection')) { typeClass = 'network'; typeTag = 'NETWORK'; }
    else if (et.includes('threat')) { typeClass = 'threat'; typeTag = 'THREAT'; }
    else if (et.includes('download') || et.includes('web')) { typeClass = 'download'; typeTag = 'DOWNLOAD'; }
    else if (et.includes('intrusion')) { typeClass = 'intrusion'; typeTag = 'INTRUSION'; }
    else if (et.includes('ransom')) { typeClass = 'ransomware'; typeTag = 'RANSOMWARE'; }
    else if (et.includes('usb')) { typeClass = 'usb'; typeTag = 'USB'; }

    const timeStr = new Date(event.timestamp || Date.now()).toLocaleTimeString();
    const displayPath = event.file_path || event.details || '—';

    item.innerHTML = `
        <div class="feed-left">
            <span class="feed-type ${typeClass}">${typeTag}</span>
            <span class="feed-path" title="${escapeHtml(displayPath)}">${escapeHtml(displayPath)}</span>
        </div>
        <span class="feed-time">${timeStr}</span>
    `;
    feed.insertBefore(item, feed.firstChild);
    while (feed.children.length > 30) feed.lastChild.remove();
}

/* ─────────────────── Dashboard ─────────────────── */
async function loadDashboardStats() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        document.getElementById('dash-scanned').innerText = stats.total_files_scanned.toLocaleString();
        document.getElementById('dash-threats').innerText = stats.total_threats;
        document.getElementById('dash-quar').innerText = stats.quarantined;
        const defsEl = document.getElementById('dash-defs');
        if (defsEl) defsEl.innerText = (stats.hash_db_size || 0).toLocaleString();

        const card = document.getElementById('dash-threats-card');
        const badge = document.getElementById('threat-badge');
        if (stats.total_threats > 0) {
            card.style.borderColor = 'var(--danger)';
            badge.innerText = stats.total_threats;
            badge.classList.add('active');
        } else {
            card.style.borderColor = 'var(--border-color)';
            badge.classList.remove('active');
        }
        // Uptime
        const u = stats.uptime_seconds || 0;
        const h = Math.floor(u / 3600), m = Math.floor((u % 3600) / 60);
        const uEl = document.getElementById('hw-uptime');
        if (uEl) uEl.innerText = `${h}h ${m}m`;
    } catch (e) { console.error('dashboard stats', e); }
}

async function loadSecurityScore() {
    try {
        const res = await fetch('/api/security-score');
        const data = await res.json();
        lastSecurityScore = data;
        renderSecurityScore(data);
    } catch (e) { console.error('security-score', e); }
}

function renderSecurityScore(data) {
    const num = document.getElementById('gauge-num');
    const grade = document.getElementById('gauge-grade');
    const verdict = document.getElementById('gauge-verdict');
    const fill = document.getElementById('gauge-fill');
    const gauge = document.getElementById('score-gauge');
    const qsVal = document.getElementById('qs-val');
    const qsGrade = document.getElementById('qs-grade');
    const qsRing = document.querySelector('.qs-ring');

    if (!data) return;
    num.innerText = data.score;
    grade.innerText = data.grade;
    verdict.innerText = ({
        protected: 'Protected',
        attention: 'Needs Attention',
        at_risk: 'At Risk',
        critical: 'Critical',
    })[data.verdict] || 'Unknown';
    qsVal.innerText = data.score;
    qsGrade.innerText = data.grade;

    // Color updates
    const colorMap = { protected: 'good', attention: 'warn', at_risk: 'bad', critical: 'critical' };
    gauge.className = `score-gauge ${colorMap[data.verdict] || ''}`;
    if (data.score >= 85) fill.setAttribute('stroke', 'url(#gaugeGrad)');
    else if (data.score >= 70) fill.setAttribute('stroke', 'url(#gaugeGradWarn)');
    else fill.setAttribute('stroke', 'url(#gaugeGradDanger)');

    // Dashoffset
    const circumference = 534;
    fill.setAttribute('stroke-dashoffset', circumference - (data.score / 100) * circumference);

    // Quick ring at top: conic-gradient via inline style
    if (qsRing) {
        const c = data.score >= 85 ? 'var(--success)' : data.score >= 70 ? 'var(--warning)' : 'var(--danger)';
        qsRing.style.background = `conic-gradient(${c} 0%, ${c} ${data.score}%, rgba(255,255,255,0.05) ${data.score}%)`;
    }

    // Pillars
    const pg = document.getElementById('pillars-grid');
    pg.innerHTML = data.pillars.map(p => {
        const pct = Math.round(100 * p.score / p.max);
        return `<div class="pillar-tile ${p.status === 'good' ? '' : p.status}">
            <div class="pillar-name">${escapeHtml(p.name)}</div>
            <div class="pillar-bar-wrap"><div class="pillar-bar" style="width:${pct}%"></div></div>
            <div class="pillar-msg">${escapeHtml(p.message)}</div>
        </div>`;
    }).join('');

    // Recommendations
    const recs = document.getElementById('hero-recs');
    if (data.recommendations && data.recommendations.length) {
        recs.innerHTML = data.recommendations.map(r =>
            `<div class="rec-item">${escapeHtml(r)}</div>`).join('');
    } else {
        recs.innerHTML = '<p class="rec-empty">Excellent — Aegis has no outstanding recommendations.</p>';
    }
}

/* ─────────────────── Scan controls ─────────────────── */
async function startScan(type) {
    let targetPath = null;
    if (type === 'custom') {
        targetPath = document.getElementById('custom-path').value.trim();
        if (!targetPath) return toast({title: 'Path required', severity: 'warning'});
    }

    document.getElementById('scan-status-panel').style.display = 'block';
    document.getElementById('scan-mode-lbl').innerText = `${type.toUpperCase()} SCAN STARTING`;

    try {
        const res = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({scan_type: type, target_path: targetPath}),
        });
        const r = await res.json();
        if (r.status === 'started') {
            startScanPoller();
        } else if (r.status === 'queued') {
            toast({title: 'Boot scan queued', message: 'Will run at next launch', severity: 'success'});
            document.getElementById('scan-status-panel').style.display = 'none';
        } else {
            toast({title: 'Could not start scan', message: r.message, severity: 'warning'});
        }
    } catch (e) { toast({title: 'Server scan launch failed', severity: 'critical'}); }
}

function startScanPoller() {
    if (scanInterval) clearInterval(scanInterval);
    scanInterval = setInterval(async () => {
        try {
            const res = await fetch('/api/scan/status');
            const data = await res.json();
            updateScanProgress(data);
            if (data.status !== 'running' && data.status !== 'paused') {
                clearInterval(scanInterval);
            }
        } catch (e) { clearInterval(scanInterval); }
    }, 1000);
}

function updateScanProgress(data) {
    if (data.running || data.status === 'running' || data.status === 'paused') {
        const panel = document.getElementById('scan-status-panel');
        panel.style.display = 'block';
        document.getElementById('scan-current-file').innerText = data.current_file || 'Evaluating directories…';
        document.getElementById('scan-progress-bar').style.width = `${data.progress}%`;
        document.getElementById('scan-progress-percent').innerText = `${data.progress}%`;
        document.getElementById('scan-scanned').innerText = data.scanned_files;
        document.getElementById('scan-threats').innerText = data.threats_found;
        document.getElementById('scan-rate').innerText = `${Math.round(data.scan_rate)} /s`;

        const eta = data.eta_seconds;
        if (eta > 0) {
            const mins = Math.floor(eta / 60);
            const secs = Math.round(eta % 60);
            document.getElementById('scan-eta').innerText = `${mins}:${secs < 10 ? '0' : ''}${secs}`;
        } else {
            document.getElementById('scan-eta').innerText = '--:--';
        }

        const pauseBtn = document.getElementById('btn-pause');
        const resumeBtn = document.getElementById('btn-resume');
        const lbl = document.getElementById('scan-mode-lbl');
        if (data.status === 'paused') {
            pauseBtn.style.display = 'none';
            resumeBtn.style.display = 'block';
            lbl.innerText = 'SCAN PAUSED';
        } else {
            pauseBtn.style.display = 'block';
            resumeBtn.style.display = 'none';
            lbl.innerText = `${(data.scan_type || 'SCAN').toUpperCase()} SCAN RUNNING`;
        }
    } else {
        document.getElementById('scan-status-panel').style.display = 'none';
        loadDashboardStats();
        loadHistory();
        loadThreats();
        loadSecurityScore();
    }
}

async function pauseScan()  { await fetch('/api/scan/pause',  {method: 'POST'}); }
async function resumeScan() { await fetch('/api/scan/resume', {method: 'POST'}); }
async function cancelScan() {
    await fetch('/api/scan/cancel', {method: 'POST'});
    document.getElementById('scan-status-panel').style.display = 'none';
}

/* ─────────────────── Threats / Quarantine ─────────────────── */
async function loadThreats() {
    try {
        const res = await fetch('/api/threats');
        const list = await res.json();
        const tbody = document.getElementById('threats-list');
        const allBtn = document.getElementById('btn-quarantine-all');
        tbody.innerHTML = '';
        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-table">System Clean: No unresolved threats.</td></tr>`;
            if (allBtn) allBtn.style.display = 'none';
            return;
        }
        if (allBtn) allBtn.style.display = 'block';
        list.forEach(t => {
            const tagClass = ['high', 'critical'].includes((t.severity || '').toLowerCase()) ? 'high' : 'medium';
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="threat-row-name">${escapeHtml(t.threat_name)}</td>
                <td><div class="threat-row-path" title="${escapeHtml(t.file_path)}">${escapeHtml(t.file_path)}</div></td>
                <td><span class="severity-tag ${escapeHtml(t.severity.toLowerCase())}">${escapeHtml(t.severity)}</span></td>
                <td>${escapeHtml(t.detection_engine || '')}</td>
                <td class="table-actions">
                    <button class="btn btn-accent" onclick="quarantineThreat(${t.id})">Quarantine</button>
                    <button class="btn btn-danger" onclick="deleteThreat(${t.id})">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) { console.error(e); }
}

async function quarantineThreat(id) {
    const r = await fetch(`/api/threats/${id}/quarantine`, {method: 'POST'});
    if (r.ok) {
        toast({title: 'Threat quarantined', severity: 'success'});
        loadThreats(); loadDashboardStats(); loadQuarantine(); loadSecurityScore();
    }
}

async function deleteThreat(id) {
    const ok = await showModal({
        title: 'Permanently delete?',
        body: 'This will erase the file from disk. This action cannot be undone.',
        confirmText: 'Delete',
        danger: true,
    });
    if (!ok) return;
    const r = await fetch(`/api/threats/${id}/delete`, {method: 'POST'});
    if (r.ok) { toast({title: 'Threat purged', severity: 'success'}); loadThreats(); loadDashboardStats(); }
}

async function quarantineAllThreats() {
    const ok = await showModal({
        title: 'Quarantine all active threats?',
        body: 'Aegis will encrypt and isolate every unresolved threat from disk.',
        confirmText: 'Quarantine All',
    });
    if (!ok) return;
    const btn = document.getElementById('btn-quarantine-all');
    if (btn) { btn.disabled = true; btn.innerText = 'Working…'; }
    try {
        const res = await fetch('/api/threats/quarantine-all', {method: 'POST'});
        if (res.ok) {
            const r = await res.json();
            toast({title: r.message, severity: 'success'});
            loadThreats(); loadDashboardStats(); loadQuarantine(); loadSecurityScore();
        }
    } finally {
        if (btn) { btn.disabled = false; btn.innerText = 'Quarantine All'; }
    }
}

async function loadQuarantine() {
    try {
        const res = await fetch('/api/quarantine');
        const data = await res.json();
        const list = data.items || data;  // backwards compat
        const tbody = document.getElementById('quarantine-list');
        const sizeLbl = document.getElementById('vault-size-lbl');
        const vaultBytes = data.vault_size || 0;
        if (sizeLbl) sizeLbl.innerText = `Vault size: ${formatBytes(vaultBytes)}`;
        tbody.innerHTML = '';
        if (!list || list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-table">Secure vault is empty.</td></tr>`;
            return;
        }
        list.forEach(q => {
            const dateStr = new Date(q.quarantined_at).toLocaleString();
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="threat-row-name">${escapeHtml(q.threat_name || '')}</td>
                <td><div class="threat-row-path" title="${escapeHtml(q.original_path)}">${escapeHtml(q.original_path)}</div></td>
                <td>${dateStr}</td>
                <td class="table-actions">
                    <button class="btn btn-accent" onclick="restoreQuarantine(${q.id})">Restore</button>
                    <button class="btn btn-danger" onclick="deleteQuarantine(${q.id})">Purge</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) { console.error(e); }
}

async function restoreQuarantine(id) {
    const r = await fetch(`/api/quarantine/${id}/restore`, {method: 'POST'});
    if (r.ok) { toast({title: 'Item restored', severity: 'info'}); loadQuarantine(); loadDashboardStats(); }
}

async function deleteQuarantine(id) {
    const ok = await showModal({title: 'Permanently purge?', body: 'This is irreversible.',
        confirmText: 'Purge', danger: true});
    if (!ok) return;
    const r = await fetch(`/api/quarantine/${id}/delete`, {method: 'POST'});
    if (r.ok) { toast({title: 'Vault item purged', severity: 'success'}); loadQuarantine(); loadDashboardStats(); }
}

async function purgeQuarantine() {
    const ok = await showModal({title: 'Purge vault?', body: 'Permanently delete all vault entries older than 30 days.',
        confirmText: 'Purge', danger: true});
    if (!ok) return;
    await fetch('/api/quarantine/purge', {method: 'POST'});
    toast({title: 'Old vault entries purged', severity: 'success'});
    loadQuarantine(); loadDashboardStats();
}

/* ─────────────────── Web Shield ─────────────────── */
async function loadWebShield() {
    try {
        const r = await fetch('/api/web-shield/status');
        const s = await r.json();
        document.getElementById('ws-checked').innerText = s.urls_checked;
        document.getElementById('ws-blocked').innerText = s.urls_blocked;
        document.getElementById('ws-dl-scanned').innerText = s.downloads_scanned;
        document.getElementById('ws-dl-blocked').innerText = s.downloads_blocked;
    } catch (e) {}
    loadBlocklist();
    loadDownloadEvents();
}

async function checkUrl() {
    const url = document.getElementById('url-input').value.trim();
    if (!url) return toast({title: 'URL required', severity: 'warning'});
    const r = await fetch('/api/web-shield/check-url', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url}),
    });
    const data = await r.json();
    const div = document.getElementById('url-result');
    div.className = `url-result show ${data.verdict}`;
    const verdictLabel = ({safe: '✓ Safe', suspicious: '⚠ Suspicious', malicious: '⛔ Malicious', blocked: '🚫 Blocked'})[data.verdict] || data.verdict;
    div.innerHTML = `
        <h4>${verdictLabel} — score ${data.score}</h4>
        <p style="font-family:'JetBrains Mono', monospace; font-size:11px; color:var(--text-dim)">${escapeHtml(data.url)}</p>
        ${data.reasons && data.reasons.length ? `<ul>${data.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>` : '<p style="margin-top:6px;color:var(--text-secondary)">No risk indicators detected.</p>'}
    `;
}

async function loadBlocklist() {
    const r = await fetch('/api/web-shield/blocklist');
    const data = await r.json();
    const grid = document.getElementById('blocklist-grid');
    if (!grid) return;
    if (data.blocklist.length === 0) {
        grid.innerHTML = '<p class="empty-feed">Blocklist is empty.</p>';
        return;
    }
    grid.innerHTML = data.blocklist.map(h => `
        <div class="bl-row">
            <span>${escapeHtml(h)}</span>
            <button class="btn btn-cancel" onclick="removeBlocklist('${escapeHtml(h).replace(/'/g, '&#39;')}')">Remove</button>
        </div>
    `).join('');
}

async function addBlocklist() {
    const host = document.getElementById('bl-input').value.trim();
    if (!host) return;
    await fetch('/api/web-shield/blocklist', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({host}),
    });
    document.getElementById('bl-input').value = '';
    toast({title: `Blocked ${host}`, severity: 'success'});
    loadBlocklist();
}

async function removeBlocklist(host) {
    await fetch('/api/web-shield/blocklist', {
        method: 'DELETE', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({host}),
    });
    loadBlocklist();
}

async function loadDownloadEvents() {
    const r = await fetch('/api/web-shield/downloads');
    const list = await r.json();
    const tbody = document.getElementById('ws-events-list');
    if (!list || list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" class="empty-table">No download activity yet.</td></tr>`;
        return;
    }
    tbody.innerHTML = list.map(e => {
        const t = new Date(e.timestamp).toLocaleString();
        const tag = e.action_taken && e.action_taken !== 'clean'
            ? `<span class="severity-tag ${e.action_taken === 'malicious' || e.action_taken === 'blocked' ? 'high' : 'medium'}">${escapeHtml(e.action_taken)}</span>`
            : `<span class="severity-tag info">clean</span>`;
        return `<tr>
            <td style="font-family:'JetBrains Mono', monospace; font-size:11px">${t}</td>
            <td>${tag}</td>
            <td class="threat-row-path" title="${escapeHtml(e.file_path || e.details)}">${escapeHtml(e.file_path || e.details)}</td>
        </tr>`;
    }).join('');
}

/* ─────────────────── Firewall ─────────────────── */
async function loadFirewall() {
    try {
        const r = await fetch('/api/firewall/status');
        const s = await r.json();
        document.getElementById('fw-engine-state').innerText = s.active ? 'ONLINE' : 'OFFLINE';
        document.getElementById('fw-engine-state').style.color = s.active ? 'var(--success)' : 'var(--danger)';
        document.getElementById('fw-intrusion-cnt').innerText = s.intrusion_events;
        document.getElementById('fw-rules-cnt').innerText = s.rules_count;
    } catch (e) {}
    loadFwConnections();
    loadFwRules();
    loadFwIntrusions();
}

async function loadFwConnections() {
    const r = await fetch('/api/firewall/connections');
    const list = await r.json();
    const tbody = document.getElementById('fw-conns-list');
    if (!list || list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-table">No established connections.</td></tr>`;
        return;
    }
    tbody.innerHTML = list.map(c => `
        <tr ${c.blocked ? 'style="background:rgba(255,45,107,0.06)"' : ''}>
            <td>${escapeHtml(c.process || '—')}</td>
            <td style="font-family:'JetBrains Mono', monospace">${c.pid || '—'}</td>
            <td style="font-family:'JetBrains Mono', monospace">${escapeHtml(c.remote_ip)}:${c.remote_port}</td>
            <td><span class="severity-tag ${c.blocked ? 'high' : 'info'}">${c.blocked ? 'BLOCKED' : escapeHtml(c.status)}</span></td>
            <td><button class="btn btn-cancel" onclick="blockIp('${escapeHtml(c.remote_ip)}')">Block IP</button></td>
        </tr>
    `).join('');
}

async function blockIp(ip) {
    await fetch('/api/firewall/rules', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rule_type: 'ip', value: ip, reason: 'User block from connections panel'}),
    });
    toast({title: `Blocked ${ip}`, severity: 'success'});
    loadFirewall();
}

async function loadFwRules() {
    const r = await fetch('/api/firewall/rules');
    const list = await r.json();
    const div = document.getElementById('fw-rules-list');
    if (!list || list.length === 0) {
        div.innerHTML = '<p class="empty-feed">No block rules.</p>';
        return;
    }
    div.innerHTML = list.map(r => `
        <div class="fw-rule-row">
            <span class="rule-type">${escapeHtml(r.type)}</span>
            <span class="rule-value">${escapeHtml(String(r.value))}</span>
            <button class="btn btn-cancel" onclick="removeFwRule('${escapeHtml(r.type)}', '${escapeHtml(String(r.value))}')">×</button>
        </div>
    `).join('');
}

async function addFirewallRule() {
    const type = document.getElementById('rule-type').value;
    const value = document.getElementById('rule-value').value.trim();
    const reason = document.getElementById('rule-reason').value.trim();
    if (!value) return toast({title: 'Value required', severity: 'warning'});
    await fetch('/api/firewall/rules', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rule_type: type, value, reason}),
    });
    document.getElementById('rule-value').value = '';
    document.getElementById('rule-reason').value = '';
    toast({title: 'Rule added', severity: 'success'});
    loadFirewall();
}

async function removeFwRule(type, value) {
    await fetch('/api/firewall/rules', {
        method: 'DELETE', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rule_type: type, value}),
    });
    loadFirewall();
}

async function loadFwIntrusions() {
    const r = await fetch('/api/firewall/intrusions');
    const list = await r.json();
    const div = document.getElementById('fw-intrusions-list');
    if (!list || list.length === 0) {
        div.innerHTML = '<p class="empty-feed">No intrusion alerts.</p>';
        return;
    }
    div.innerHTML = list.slice().reverse().map(e => `
        <div class="intrusion-row ${escapeHtml(e.severity)}">
            <div class="ir-kind">${escapeHtml(e.kind)}</div>
            <div class="ir-details">${escapeHtml(e.details)}</div>
            <div class="ir-time">${new Date(e.timestamp).toLocaleString()}</div>
        </div>
    `).join('');
}

/* ─────────────────── Ransomware Shield ─────────────────── */
async function loadRansomware() {
    try {
        const r = await fetch('/api/ransomware/status');
        const s = await r.json();
        document.getElementById('rs-state-lbl').innerText =
            `${s.active ? 'ACTIVE' : 'OFFLINE'} — watching ${s.protected_folders.length} folder(s)`;
        const grid = document.getElementById('rs-folders-grid');
        if (!s.protected_folders.length) {
            grid.innerHTML = '<p class="empty-feed">No protected folders configured.</p>';
        } else {
            grid.innerHTML = s.protected_folders.map(f => `
                <div class="folder-row">
                    <span class="fp" title="${escapeHtml(f)}">${escapeHtml(f)}</span>
                    <button class="btn btn-cancel" onclick="removeProtectedFolder('${escapeHtml(f).replace(/\\/g, '\\\\')}')">Remove</button>
                </div>
            `).join('');
        }
    } catch (e) {}

    // Events
    const er = await fetch('/api/ransomware/events');
    const events = await er.json();
    const list = document.getElementById('rs-events-list');
    if (!events || events.length === 0) {
        list.innerHTML = '<p class="empty-feed">No ransomware activity detected.</p>';
    } else {
        list.innerHTML = events.map(e => `
            <div class="intrusion-row ${escapeHtml(e.severity)}">
                <div class="ir-kind">${escapeHtml(e.kind)}</div>
                <div class="ir-details">${escapeHtml(e.path || '')} — ${escapeHtml(e.details)}</div>
                <div class="ir-time">${new Date(e.timestamp).toLocaleString()}</div>
            </div>
        `).join('');
    }
}

async function addProtectedFolder() {
    const folder = await showInputModal({
        title: 'Add Protected Folder',
        body: 'Aegis will monitor this folder for ransomware behavior.',
        placeholder: 'C:\\Users\\YOU\\Documents',
    });
    if (!folder) return;
    const r = await fetch('/api/ransomware/folders', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({folder}),
    });
    if (r.ok) { toast({title: 'Folder added', severity: 'success'}); loadRansomware(); }
    else toast({title: 'Failed to add folder', severity: 'critical'});
}

async function removeProtectedFolder(folder) {
    await fetch('/api/ransomware/folders', {
        method: 'DELETE', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({folder}),
    });
    toast({title: 'Folder removed', severity: 'info'});
    loadRansomware();
}

/* ─────────────────── Vulnerabilities ─────────────────── */
async function loadVulnerabilities(force) {
    const list = document.getElementById('vuln-list');
    list.innerHTML = '<p class="empty-feed">Scanning… first scan can take ~30 seconds.</p>';
    try {
        const r = await fetch(`/api/vulnerabilities?force=${force ? 1 : 0}`);
        const data = await r.json();
        renderVulnerabilities(data);
        loadSecurityScore();  // refresh score with new vuln data
    } catch (e) {
        list.innerHTML = '<p class="empty-feed">Could not run vulnerability scan.</p>';
    }
}

function renderVulnerabilities(data) {
    const summary = document.getElementById('vuln-summary');
    const counts = data.counts || {};
    summary.innerHTML = `
        <div class="vs critical"><h4>Critical</h4><p>${counts.critical || 0}</p></div>
        <div class="vs high"><h4>High</h4><p>${counts.high || 0}</p></div>
        <div class="vs"><h4>Medium</h4><p>${counts.medium || 0}</p></div>
        <div class="vs"><h4>Info</h4><p>${counts.info || 0}</p></div>
    `;
    const list = document.getElementById('vuln-list');
    if (!data.findings || data.findings.length === 0) {
        list.innerHTML = '<p class="empty-feed">No vulnerability data available.</p>';
        return;
    }
    list.innerHTML = data.findings.map(f => `
        <div class="vuln-row ${escapeHtml(f.severity)}">
            <div class="vt">${escapeHtml(f.title)}</div>
            <div class="vv">${escapeHtml(f.value)}</div>
            <span class="severity-tag ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
            ${f.recommendation ? `<div class="vr">→ ${escapeHtml(f.recommendation)}</div>` : ''}
        </div>
    `).join('');
}

/* ─────────────────── Network ─────────────────── */
async function loadNetwork() {
    try {
        const r = await fetch('/api/network/connections');
        const conns = await r.json();
        const tbody = document.getElementById('net-conns-list');
        if (!conns || conns.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-table">No connections.</td></tr>`;
        } else {
            tbody.innerHTML = conns.slice(0, 200).map(c => `
                <tr>
                    <td>${escapeHtml(c.process || '—')}</td>
                    <td style="font-family:'JetBrains Mono', monospace; font-size:11px">${escapeHtml(c.local || '—')}</td>
                    <td style="font-family:'JetBrains Mono', monospace; font-size:11px">${escapeHtml(c.remote || '—')}</td>
                    <td><span class="severity-tag info">${escapeHtml(c.status)}</span></td>
                </tr>
            `).join('');
        }
    } catch (e) {}

    try {
        const ifr = await fetch('/api/network/interfaces');
        const ifaces = await ifr.json();
        const div = document.getElementById('net-ifaces-list');
        if (!ifaces || ifaces.length === 0) {
            div.innerHTML = '<p class="empty-feed">No interfaces.</p>';
        } else {
            div.innerHTML = ifaces.map(i => `
                <div class="fw-rule-row" style="flex-direction:column; align-items:stretch">
                    <div style="display:flex; justify-content:space-between; align-items:center">
                        <strong style="color:var(--text-main)">${escapeHtml(i.name)}</strong>
                        <span class="severity-tag ${i.up ? 'info' : 'low'}">${i.up ? 'UP' : 'DOWN'}</span>
                    </div>
                    <div style="font-family:'JetBrains Mono', monospace; font-size:10px; color:var(--text-dim); margin-top:4px">
                        ${i.addresses.slice(0, 4).map(a => escapeHtml(a)).join(', ')}
                    </div>
                </div>
            `).join('');
        }
    } catch (e) {}

    try {
        const s = await (await fetch('/api/network/stats')).json();
        document.getElementById('net-bytes-sent').innerText = formatBytes(s.bytes_sent || 0);
        document.getElementById('net-bytes-recv').innerText = formatBytes(s.bytes_recv || 0);
        document.getElementById('net-pkts-sent').innerText = (s.packets_sent || 0).toLocaleString();
        document.getElementById('net-pkts-recv').innerText = (s.packets_recv || 0).toLocaleString();
    } catch (e) {}
}

/* ─────────────────── Processes ─────────────────── */
function changeProcessSort(s) {
    processSort = s;
    document.querySelectorAll('.seg-btn').forEach(b => b.classList.toggle('active', b.dataset.sort === s));
    loadProcesses();
}

function startProcessLoop() {
    loadProcesses();
    if (processTimer) clearInterval(processTimer);
    processTimer = setInterval(loadProcesses, 4000);
}

async function loadProcesses() {
    try {
        const r = await fetch(`/api/processes?sort=${processSort}&limit=100`);
        const list = await r.json();
        const tbody = document.getElementById('proc-list');
        if (!list || list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-table">No processes.</td></tr>`;
            return;
        }
        tbody.innerHTML = list.map(p => `
            <tr class="proc-row ${p.suspicious ? 'suspicious' : ''}">
                <td><strong>${escapeHtml(p.name || '(unknown)')}</strong>${p.suspicious ? '<span class="sus-tag">SUSPICIOUS</span>' : ''}</td>
                <td style="font-family:'JetBrains Mono', monospace">${p.pid}</td>
                <td>${escapeHtml(p.user || '—')}</td>
                <td style="font-family:'JetBrains Mono', monospace">${(p.cpu || 0).toFixed(1)}%</td>
                <td style="font-family:'JetBrains Mono', monospace">${(p.memory || 0).toFixed(1)}%</td>
                <td><span class="severity-tag info">${escapeHtml(p.status || '')}</span></td>
                <td><button class="btn btn-danger" onclick="killProcess(${p.pid})">Kill</button></td>
            </tr>
        `).join('');
    } catch (e) {}
}

async function killProcess(pid) {
    const ok = await showModal({
        title: `Terminate process PID ${pid}?`,
        body: 'The process and its children will be ended immediately.',
        confirmText: 'Terminate',
        danger: true,
    });
    if (!ok) return;
    const r = await fetch('/api/processes/kill', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({pid}),
    });
    if (r.ok) { toast({title: `PID ${pid} terminated`, severity: 'success'}); loadProcesses(); }
    else toast({title: 'Failed to terminate', severity: 'critical'});
}

/* ─────────────────── Startup items ─────────────────── */
async function loadStartup() {
    try {
        const r = await fetch('/api/startup');
        const list = await r.json();
        const tbody = document.getElementById('startup-list');
        if (!list || list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-table">No startup entries found.</td></tr>`;
            return;
        }
        tbody.innerHTML = list.map(e => `
            <tr>
                <td><strong>${escapeHtml(e.name)}</strong></td>
                <td><span class="severity-tag info">${escapeHtml(e.type)}</span></td>
                <td style="font-family:'JetBrains Mono', monospace; font-size:10px">${escapeHtml(e.hive)}\\${escapeHtml(e.path)}</td>
                <td><div class="threat-row-path" title="${escapeHtml(e.command)}">${escapeHtml(e.command)}</div></td>
                <td><button class="btn btn-danger" onclick='removeStartup(${JSON.stringify(e).replace(/'/g, '&#39;')})'>Remove</button></td>
            </tr>
        `).join('');
    } catch (e) {}
}

async function removeStartup(entry) {
    const ok = await showModal({
        title: 'Remove startup entry?',
        body: `${entry.name} will no longer launch when Windows starts.`,
        confirmText: 'Remove', danger: true,
    });
    if (!ok) return;
    const r = await fetch('/api/startup/remove', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({hive: entry.hive, path: entry.path, name: entry.name}),
    });
    if (r.ok) { toast({title: `Removed ${entry.name}`, severity: 'success'}); loadStartup(); }
    else toast({title: 'Could not remove entry (admin rights?)', severity: 'critical'});
}

/* ─────────────────── Optimizer ─────────────────── */
async function runOptimizerScan() {
    const j = document.getElementById('opt-junk-val');
    const c = document.getElementById('opt-cache-val');
    const r = document.getElementById('opt-reg-val');
    if (j) j.innerText = 'Scanning…';
    if (c) c.innerText = 'Scanning…';
    if (r) r.innerText = 'Scanning…';
    try {
        const res = await fetch('/api/optimizer/scan');
        const data = await res.json();
        if (j) j.innerText = data.junk_size;
        if (c) c.innerText = data.browser_cache || '—';
        if (r) r.innerText = `${data.broken_registries} items`;
    } catch (e) {}
}

async function runOptimization() {
    const temp = document.getElementById('chk-temp').checked;
    const reg = document.getElementById('chk-reg').checked;
    const logs = document.getElementById('chk-logs').checked;
    const browser_cache = document.getElementById('chk-browser-cache').checked;
    if (!temp && !reg && !logs && !browser_cache)
        return toast({title: 'Select at least one target', severity: 'warning'});

    const ring = document.querySelector('.boost-ring');
    const pct = document.querySelector('.boost-percent');
    ring.style.borderTopColor = 'var(--success)';
    pct.innerText = 'CLEANING';
    try {
        const res = await fetch('/api/optimizer/clean', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({temp, reg, logs, browser_cache}),
        });
        const r = await res.json();
        setTimeout(() => {
            pct.innerText = 'BOOSTED';
            toast({title: 'Optimization complete', message: r.message, severity: 'success'});
            runOptimizerScan();
            loadDashboardStats();
        }, 1100);
    } catch (e) {
        pct.innerText = 'FAILED';
        toast({title: 'Optimizer failed', severity: 'critical'});
    }
}

/* ─────────────────── Settings ─────────────────── */
async function loadSettings() {
    try {
        const r = await fetch('/api/settings');
        const cfg = await r.json();
        document.getElementById('cfg-perf').checked = !!cfg.performance_mode;
        document.getElementById('cfg-quar').checked = !!cfg.auto_quarantine;
        document.getElementById('cfg-arch').checked = !!cfg.scan_archives;
        document.getElementById('cfg-vt-key').value = cfg.virustotal_api_key || '';
        document.getElementById('cfg-realtime').checked = !!cfg.realtime_protection;
        document.getElementById('cfg-web-shield').checked = !!cfg.web_shield_enabled;
        document.getElementById('cfg-firewall').checked = !!cfg.firewall_enabled;
        document.getElementById('cfg-ransomware').checked = !!cfg.ransomware_shield_enabled;
        document.getElementById('cfg-notif').checked = !!cfg.notifications_enabled;
        document.getElementById('cfg-game').checked = !!cfg.game_mode;
        document.getElementById('cfg-sens').value = cfg.heuristic_sensitivity || 'medium';
        notifMuted = !!cfg.game_mode;
        const btn = document.getElementById('btn-game-mode');
        if (btn) btn.classList.toggle('active', notifMuted);
    } catch (e) {}
}

async function saveSettings() {
    const payload = {
        performance_mode:         document.getElementById('cfg-perf').checked,
        auto_quarantine:          document.getElementById('cfg-quar').checked,
        scan_archives:            document.getElementById('cfg-arch').checked,
        virustotal_api_key:       document.getElementById('cfg-vt-key').value.trim(),
        realtime_protection:      document.getElementById('cfg-realtime').checked,
        web_shield_enabled:       document.getElementById('cfg-web-shield').checked,
        firewall_enabled:         document.getElementById('cfg-firewall').checked,
        ransomware_shield_enabled:document.getElementById('cfg-ransomware').checked,
        notifications_enabled:    document.getElementById('cfg-notif').checked,
        game_mode:                document.getElementById('cfg-game').checked,
        heuristic_sensitivity:    document.getElementById('cfg-sens').value,
    };
    notifMuted = payload.game_mode;
    try {
        const res = await fetch('/api/settings', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        if (res.ok) {
            toast({title: 'Settings saved', severity: 'success'});
            loadSettings();
            loadSecurityScore();
        }
    } catch (e) { toast({title: 'Could not save settings', severity: 'critical'}); }
}

async function toggleGameMode() {
    const cfg = await (await fetch('/api/settings')).json();
    const next = !cfg.game_mode;
    await fetch('/api/settings', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({game_mode: next, notifications_enabled: !next ? true : cfg.notifications_enabled}),
    });
    notifMuted = next;
    document.getElementById('btn-game-mode').classList.toggle('active', next);
    toast({
        title: next ? '🎮 Game Mode enabled' : 'Game Mode disabled',
        message: next ? 'Toasts will be silenced (critical alerts still shown).' : 'Notifications restored.',
        severity: 'info',
    });
}

/* ─────────────────── History ─────────────────── */
async function loadHistory() {
    try {
        const r = await fetch('/api/history');
        const list = await r.json();
        const tbody = document.getElementById('history-list');
        if (!list || list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-table">No scan histories yet.</td></tr>`;
            return;
        }
        tbody.innerHTML = list.map(h => {
            const dateStr = new Date(h.start_time).toLocaleString();
            const duration = h.end_time ? `${Math.round((new Date(h.end_time) - new Date(h.start_time)) / 1000)}s` : 'In Progress';
            return `<tr>
                <td><strong>${escapeHtml(h.scan_type.toUpperCase())}</strong></td>
                <td>${dateStr}</td>
                <td>${duration}</td>
                <td>${h.files_scanned.toLocaleString()}</td>
                <td class="${h.threats_found > 0 ? 'threat-row-name' : ''}">${h.threats_found} threats</td>
                <td><span class="pulse-indicator" style="background:transparent; border:none">${escapeHtml(h.status.toUpperCase())}</span></td>
            </tr>`;
        }).join('');
    } catch (e) {}
}

/* ─────────────────── Whitelist ─────────────────── */
async function loadWhitelist() {
    try {
        const r = await fetch('/api/whitelist');
        const rules = await r.json();
        const tbody = document.getElementById('whitelist-list');
        if (!rules || rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-table">No exclusion rules.</td></tr>`;
            return;
        }
        tbody.innerHTML = rules.map(rule => `
            <tr>
                <td class="threat-row-path" title="${escapeHtml(rule.file_path || '')}">${escapeHtml(rule.file_path) || '<span class="text-dim">N/A</span>'}</td>
                <td style="font-family:'JetBrains Mono', monospace; font-size:10px">${escapeHtml(rule.file_hash) || '<span class="text-dim">N/A</span>'}</td>
                <td style="color:var(--text-dim)">${escapeHtml(rule.reason || 'No note')}</td>
                <td style="font-size:11px; font-family:'JetBrains Mono', monospace">${new Date(rule.added_at).toLocaleString()}</td>
                <td><button class="btn btn-cancel" onclick="removeWhitelistRule(${rule.id})">Remove</button></td>
            </tr>
        `).join('');
    } catch (e) {}
}

async function addWhitelistRule() {
    const file_path = document.getElementById('wl-path-input').value.trim();
    const note = document.getElementById('wl-note-input').value.trim();
    if (!file_path) return toast({title: 'Path required', severity: 'warning'});
    const r = await fetch('/api/whitelist', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({file_path, note}),
    });
    const data = await r.json();
    toast({title: data.message || 'Rule added', severity: 'success'});
    document.getElementById('wl-path-input').value = '';
    document.getElementById('wl-note-input').value = '';
    loadWhitelist(); loadQuarantine(); loadDashboardStats();
}

async function addHashWhitelistRule() {
    const file_hash = document.getElementById('wl-hash-input').value.trim();
    if (!file_hash || file_hash.length !== 64)
        return toast({title: 'Hash must be 64 chars (SHA-256)', severity: 'warning'});
    const r = await fetch('/api/whitelist', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({file_hash, note: 'Hash exclusion'}),
    });
    const data = await r.json();
    toast({title: data.message || 'Rule added', severity: 'success'});
    document.getElementById('wl-hash-input').value = '';
    loadWhitelist();
}

async function removeWhitelistRule(id) {
    const ok = await showModal({title: 'Delete exclusion rule?', body: 'Files in this path may be flagged again.',
        confirmText: 'Delete', danger: true});
    if (!ok) return;
    await fetch(`/api/whitelist/${id}`, {method: 'DELETE'});
    loadWhitelist();
}

/* ─────────────────── Reports / Analytics ─────────────────── */
async function loadReports() {
    try {
        const r = await fetch('/api/reports');
        const data = await r.json();
        renderReports(data);
    } catch (e) { console.error(e); }
}

function renderReports(data) {
    // Threats time-series (line)
    const tt = data.threats_over_time || [];
    const st = data.scans_over_time || [];

    drawChart('chart-threats', 'line', {
        labels: tt.map(d => d.date.slice(5)),
        datasets: [{
            label: 'Threats',
            data: tt.map(d => d.count),
            borderColor: '#ff2d6b',
            backgroundColor: 'rgba(255,45,107,0.15)',
            tension: 0.35, fill: true,
        }],
    });

    drawChart('chart-scans', 'bar', {
        labels: st.map(d => d.date.slice(5)),
        datasets: [{
            label: 'Scans',
            data: st.map(d => d.count),
            backgroundColor: 'rgba(0,240,255,0.5)',
            borderColor: '#00f0ff',
            borderWidth: 1,
        }],
    });

    const sev = data.severity_breakdown || {};
    drawChart('chart-severity', 'doughnut', {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [sev.critical || 0, sev.high || 0, sev.medium || 0, sev.low || 0],
            backgroundColor: ['#ff2d6b', '#ff8c00', '#ffb700', '#62a5ff'],
            borderColor: 'rgba(255,255,255,0.05)',
            borderWidth: 2,
        }],
    });

    const eng = data.engine_breakdown || {};
    const engLabels = Object.keys(eng);
    const engData = engLabels.map(k => eng[k]);
    drawChart('chart-engine', 'bar', {
        labels: engLabels.length ? engLabels : ['No data'],
        datasets: [{
            label: 'Detections',
            data: engData.length ? engData : [0],
            backgroundColor: 'rgba(124,77,255,0.5)',
            borderColor: '#7c4dff',
            borderWidth: 1,
        }],
    }, {indexAxis: 'y'});
}

function drawChart(id, type, data, extraOpts={}) {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    if (charts[id]) { charts[id].destroy(); charts[id] = null; }
    const ctx = canvas.getContext('2d');
    const opts = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: '#98a3bd' } },
        },
        scales: type === 'doughnut' ? undefined : {
            x: { ticks: { color: '#5b6781' }, grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { ticks: { color: '#5b6781' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
        },
        ...extraOpts,
    };
    charts[id] = new Chart(ctx, {type, data, options: opts});
}

/* ─────────────────── Threat Intelligence ─────────────────── */
async function loadThreatIntel() {
    try {
        const r = await fetch('/api/threat-intel');
        const data = await r.json();
        const grid = document.getElementById('intel-grid');
        grid.innerHTML = data.cards.map(c => `
            <div class="intel-card">
                <span class="ic-tag">${escapeHtml(c.category)}</span>
                <h3>${escapeHtml(c.title)}</h3>
                <p>${escapeHtml(c.summary)}</p>
                <div class="ic-meta">
                    <span class="severity-tag ${escapeHtml(c.severity)}">${escapeHtml(c.severity)}</span>
                    · ${new Date(c.published_at).toLocaleString()}
                </div>
            </div>
        `).join('');
    } catch (e) {}
}

/* ─────────────────── Scheduler ─────────────────── */
async function loadSchedules() {
    try {
        const r = await fetch('/api/schedules');
        const list = await r.json();
        const tbody = document.getElementById('sched-list');
        if (!list || list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-table">No scheduled scans.</td></tr>`;
            return;
        }
        const DOW = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
        tbody.innerHTML = list.map(s => `
            <tr>
                <td><strong>${escapeHtml(s.schedule_type)}</strong></td>
                <td>${escapeHtml(s.scan_type)}</td>
                <td>${escapeHtml(s.time || '—')}</td>
                <td>${s.day_of_week >= 0 ? DOW[s.day_of_week] : '—'}</td>
                <td>
                    <label class="switch" style="transform:scale(0.8)">
                        <input type="checkbox" ${s.enabled ? 'checked' : ''} onchange="toggleSchedule(${s.id}, this.checked)">
                        <span class="slider"></span>
                    </label>
                </td>
                <td><button class="btn btn-danger" onclick="removeSchedule(${s.id})">Remove</button></td>
            </tr>
        `).join('');
    } catch (e) {}
}

async function addSchedule() {
    const payload = {
        schedule_type: document.getElementById('sched-type').value,
        scan_type:     document.getElementById('sched-scan').value,
        time:          document.getElementById('sched-time').value,
        day_of_week:   parseInt(document.getElementById('sched-dow').value),
    };
    await fetch('/api/schedules', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
    });
    toast({title: 'Schedule added', severity: 'success'});
    loadSchedules();
}

async function toggleSchedule(id, enabled) {
    await fetch(`/api/schedules/${id}/toggle`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled}),
    });
}

async function removeSchedule(id) {
    const ok = await showModal({title: 'Delete schedule?', confirmText: 'Delete', danger: true});
    if (!ok) return;
    await fetch(`/api/schedules/${id}`, {method: 'DELETE'});
    loadSchedules();
}

/* ─────────────────── Password Health ─────────────────── */
async function checkPassword() {
    const pw = document.getElementById('pw-input').value;
    if (!pw) return toast({title: 'Type a password first', severity: 'warning'});
    const checkBreach = document.getElementById('pw-breach').checked;

    const div = document.getElementById('pw-result');
    div.className = 'pw-result show';
    div.innerHTML = '<p class="empty-feed">Analyzing…</p>';

    try {
        const r = await fetch('/api/password-health', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({password: pw, check_breach: checkBreach}),
        });
        const data = await r.json();
        const color = data.score >= 80 ? 'var(--success)' : data.score >= 50 ? 'var(--warning)' : 'var(--danger)';
        const breach = data.breach || {};
        div.innerHTML = `
            <h3 style="color:${color}; font-size:18px">Result: ${escapeHtml(data.label)} (${data.score}/100)</h3>
            <div class="pw-meter"><div class="pw-meter-fill" style="width:${data.score}%"></div></div>
            <div class="pw-grid">
                <div class="pw-tile"><h4>Length</h4><div class="v">${data.length}</div></div>
                <div class="pw-tile"><h4>Char Classes</h4><div class="v">${data.classes} / 4</div></div>
                <div class="pw-tile"><h4>Breach DB</h4><div class="v" style="color:${breach.pwned ? 'var(--danger)' : 'var(--success)'}">
                    ${breach.checked ? (breach.pwned ? `${breach.occurrences} hits` : 'Clean') : 'Skipped'}
                </div></div>
            </div>
            <ul class="pw-list" style="margin-top:14px">
                ${(data.issues || []).map(i => `<li class="issue">${escapeHtml(i)}</li>`).join('')}
                ${(data.tips || []).map(t => `<li class="tip">${escapeHtml(t)}</li>`).join('')}
                ${breach.pwned ? `<li class="breach">⚠ This password has appeared in ${breach.occurrences} known data breaches — change it everywhere it's used.</li>` : ''}
            </ul>
        `;
    } catch (e) {
        div.innerHTML = '<p class="empty-feed">Could not check password.</p>';
    }
}

/* ─────────────────── Notifications panel ─────────────────── */
async function updateNotifBadge() {
    try {
        const r = await fetch('/api/notifications?unread=1&limit=1');
        const data = await r.json();
        document.getElementById('notif-dot').style.display = data.unread > 0 ? 'block' : 'none';
    } catch (e) {}
}

async function openNotificationsPanel() {
    const r = await fetch('/api/notifications?limit=30');
    const data = await r.json();
    const body = document.createElement('div');
    body.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px">
            <strong style="font-size:14px">Recent Notifications</strong>
            <div style="display:flex; gap:6px">
                <button class="btn btn-cancel" onclick="markAllRead()" style="padding:6px 12px; font-size:11px">Mark all read</button>
                <button class="btn btn-danger" onclick="clearAllNotifs()" style="padding:6px 12px; font-size:11px">Clear</button>
            </div>
        </div>
        <div class="notif-panel-list" id="notif-panel-list">
            ${data.items.length === 0 ? '<p class="empty-feed">No notifications yet.</p>' :
                data.items.map(n => `
                    <div class="notif-row ${escapeHtml(n.severity || 'info')} ${!n.read_at ? 'unread' : ''}">
                        <div class="ntitle">${escapeHtml(n.title)}</div>
                        <div class="nmsg">${escapeHtml(n.message || '')}</div>
                        <div class="nmeta">${new Date(n.created_at).toLocaleString()}</div>
                    </div>
                `).join('')}
        </div>
    `;
    await showModal({title: 'Notifications', body, confirmText: 'Close', cancelText: 'Dismiss'});
    updateNotifBadge();
}

async function markAllRead() {
    await fetch('/api/notifications/read-all', {method: 'POST'});
    updateNotifBadge();
}

async function clearAllNotifs() {
    await fetch('/api/notifications', {method: 'DELETE'});
    updateNotifBadge();
    document.getElementById('modal-root').classList.remove('show');
}

/* ─────────────────── Helpers ─────────────────── */
function formatBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
    return `${(n / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}
