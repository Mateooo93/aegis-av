/*
   Aegis AV - Premium Client Core Engine
   Handles WebSockets, asynchronous API routers, and hardware-accelerated transitions
*/

let socket = null;
let currentActivePage = 'dashboard';
let scanInterval = null;

// Initialize on Load
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initWebSocket();
    loadDashboardStats();
    loadSettings();
    loadHistory();
    loadQuarantine();
    loadThreats();
    loadWhitelist();
    runOptimizerScan();

    // Re-check periodically
    setInterval(loadDashboardStats, 5000);
});

// 1. Instant Tab-Switching Router
function initNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const pages = document.querySelectorAll('.page');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-target');
            if (target === currentActivePage) return;

            // Update Sidebar Navigation state instantly (0ms)
            navButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Swap Pages instantly with CSS Fade transitions
            pages.forEach(p => {
                p.classList.remove('active');
                if (p.id === target) {
                    p.classList.add('active');
                }
            });

            currentActivePage = target;
            
            // Defer heavy data updates so the tab visual transition stays at 144 FPS
            setTimeout(() => {
                triggerPageRefresh(target);
            }, 10);
        });
    });
}

function triggerPageRefresh(pageId) {
    if (pageId === 'dashboard') loadDashboardStats();
    else if (pageId === 'threats') loadThreats();
    else if (pageId === 'quarantine') loadQuarantine();
    else if (pageId === 'history') loadHistory();
    else if (pageId === 'optimizer') runOptimizerScan();
    else if (pageId === 'settings') loadSettings();
    else if (pageId === 'whitelist') loadWhitelist();
}

// 2. Real-Time WebSockets Engine
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        console.log('Connected to Aegis Core WebSocket Gateway.');
        updateConnectionStatus(true);
    };

    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // Handle Live Hardware Stats
        if (data.type === 'system_stats') {
            document.getElementById('cpu-bar').style.width = `${data.cpu}%`;
            document.getElementById('cpu-lbl').innerText = `${data.cpu}%`;
            document.getElementById('ram-bar').style.width = `${data.ram}%`;
            document.getElementById('ram-lbl').innerText = `${data.ram}%`;
            
            if (data.performance_mode) {
                document.getElementById('hw-priority').innerText = 'HIGH PRIORITY';
                document.getElementById('hw-priority').className = 'alloc-val highlight';
            } else {
                document.getElementById('hw-priority').innerText = 'STANDARD';
                document.getElementById('hw-priority').className = 'alloc-val';
            }
        }

        // Handle Active Monitor Events
        if (data.type === 'monitor_event') {
            appendMonitorFeed(data.event);
        }

        // Handle Scan Progress updates
        if (data.type === 'scan_progress') {
            updateScanProgress(data.status);
        }
    };

    socket.onclose = () => {
        console.warn('WebSocket closed. Attempting reconnect in 3s...');
        updateConnectionStatus(false);
        setTimeout(initWebSocket, 3000);
    };
}

// Update connection in sidebar
function updateConnectionStatus(connected) {
    const dot = document.querySelector('.conn-dot');
    const title = document.querySelector('.status-title');
    const subtitle = document.querySelector('.status-subtitle');

    if (connected) {
        dot.className = 'conn-dot green';
        title.innerText = 'System Protected';
        subtitle.innerText = 'Engine Online';
    } else {
        dot.className = 'conn-dot red';
        title.innerText = 'Engine Offline';
        subtitle.innerText = 'Connecting...';
    }
}

// 3. Active Monitor Feed
function appendMonitorFeed(event) {
    const feed = document.getElementById('monitor-feed-list');
    const empty = feed.querySelector('.empty-feed');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = 'feed-item';
    
    // Type Tag class mapping
    let typeClass = 'write';
    let typeTag = 'FILE';
    if (event.event_type.toLowerCase() === 'process') { typeClass = 'process'; typeTag = 'PROCESS'; }
    else if (event.event_type.toLowerCase() === 'network') { typeClass = 'network'; typeTag = 'NETWORK'; }
    else if (event.event_type.toLowerCase() === 'threat') { typeClass = 'threat'; typeTag = 'THREAT'; }

    // Format Timestamp
    const timeStr = new Date(event.timestamp).toLocaleTimeString();

    item.innerHTML = `
        <div class="feed-left">
            <span class="feed-type ${typeClass}">${typeTag}</span>
            <span class="feed-path" title="${event.file_path || event.details}">${event.file_path || event.details}</span>
        </div>
        <span class="feed-time">${timeStr}</span>
    `;

    feed.insertBefore(item, feed.firstChild);

    // Caps length at 25 entries to save browser memory
    if (feed.children.length > 25) {
        feed.lastChild.remove();
    }
}

// 4. Async Dashboard Loader
async function loadDashboardStats() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        
        document.getElementById('dash-scanned').innerText = stats.total_files_scanned.toLocaleString();
        document.getElementById('dash-threats').innerText = stats.total_threats;
        document.getElementById('dash-quar').innerText = stats.quarantined;

        const threatsCard = document.getElementById('dash-threats-card');
        const badge = document.getElementById('threat-badge');
        
        if (stats.total_threats > 0) {
            threatsCard.style.borderColor = 'var(--danger)';
            badge.innerText = stats.total_threats;
            badge.classList.add('active');
        } else {
            threatsCard.style.borderColor = 'var(--border-color)';
            badge.classList.remove('active');
        }
    } catch (e) {
        console.error('Error fetching dashboard stats', e);
    }
}

// 5. Scanners Logic
async function startScan(type) {
    let targetPath = null;
    if (type === 'custom') {
        targetPath = document.getElementById('custom-path').value.trim();
        if (!targetPath) return alert('Please enter a valid directory target path!');
    }

    document.getElementById('scan-status-panel').style.display = 'block';
    document.getElementById('scan-mode-lbl').innerText = `${type.toUpperCase()} SCAN RUNNING`;
    
    try {
        const res = await fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_type: type, target_path: targetPath })
        });
        const r = await res.json();
        if (r.status === 'started') {
            console.log('Scan started successfully');
            startScanPoller();
        } else {
            alert(`Could not start scan: ${r.message}`);
        }
    } catch (e) {
        alert('Server scan launch failed');
    }
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
        } catch (e) {
            clearInterval(scanInterval);
        }
    }, 1000);
}

function updateScanProgress(data) {
    if (data.running || data.status === 'running' || data.status === 'paused') {
        document.getElementById('scan-status-panel').style.display = 'block';
        document.getElementById('scan-current-file').innerText = data.current_file || 'Evaluating directories...';
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

        if (data.status === 'paused') {
            document.getElementById('btn-pause').style.display = 'none';
            document.getElementById('btn-resume').style.display = 'block';
            document.getElementById('scan-mode-lbl').innerText = `SCAN PAUSED`;
        } else {
            document.getElementById('btn-pause').style.display = 'block';
            document.getElementById('btn-resume').style.display = 'none';
            document.getElementById('scan-mode-lbl').innerText = `SCAN RUNNING`;
        }
    } else {
        document.getElementById('scan-status-panel').style.display = 'none';
        loadDashboardStats();
        loadHistory();
        loadThreats();
    }
}

async function pauseScan() {
    await fetch('/api/scan/pause', { method: 'POST' });
}

async function resumeScan() {
    await fetch('/api/scan/resume', { method: 'POST' });
}

async function cancelScan() {
    await fetch('/api/scan/cancel', { method: 'POST' });
    document.getElementById('scan-status-panel').style.display = 'none';
}

// 6. Threats Log Panel
async function loadThreats() {
    try {
        const res = await fetch('/api/threats');
        const list = await res.json();
        
        const tbody = document.getElementById('threats-list');
        const quarantineAllBtn = document.getElementById('btn-quarantine-all');
        tbody.innerHTML = '';

        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-table">System Clean: No unresolved threats registered.</td></tr>`;
            if (quarantineAllBtn) quarantineAllBtn.style.display = 'none';
            return;
        }

        if (quarantineAllBtn) quarantineAllBtn.style.display = 'block';

        list.forEach(t => {
            const tr = document.createElement('tr');
            const tagClass = t.severity.toLowerCase() === 'high' || t.severity.toLowerCase() === 'critical' ? 'high' : 'medium';
            
            tr.innerHTML = `
                <td class="threat-row-name">${t.threat_name}</td>
                <td><div class="threat-row-path" title="${t.file_path}">${t.file_path}</div></td>
                <td><span class="severity-tag ${tagClass}">${t.severity}</span></td>
                <td>${t.detection_engine}</td>
                <td class="table-actions">
                    <button class="btn btn-accent" onclick="quarantineThreat(${t.id})">Quarantine</button>
                    <button class="btn btn-danger" onclick="deleteThreat(${t.id})">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error(e);
    }
}

async function quarantineThreat(id) {
    const res = await fetch(`/api/threats/${id}/quarantine`, { method: 'POST' });
    if (res.ok) {
        loadThreats();
        loadDashboardStats();
        loadQuarantine();
    }
}

async function deleteThreat(id) {
    if (!confirm('Are you absolutely sure you want to permanently delete this file?')) return;
    const res = await fetch(`/api/threats/${id}/delete`, { method: 'POST' });
    if (res.ok) {
        loadThreats();
        loadDashboardStats();
    }
}

async function quarantineAllThreats() {
    if (!confirm('Are you absolutely sure you want to quarantine all active threats?')) return;
    const btn = document.getElementById('btn-quarantine-all');
    if (btn) {
        btn.disabled = true;
        btn.innerText = 'Quarantining...';
    }
    try {
        const res = await fetch('/api/threats/quarantine-all', { method: 'POST' });
        if (res.ok) {
            const r = await res.json();
            alert(r.message);
            loadThreats();
            loadDashboardStats();
            loadQuarantine();
        } else {
            alert('Failed to quarantine threats.');
        }
    } catch (e) {
        alert('Network error during bulk quarantine operation.');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = 'Quarantine All';
        }
    }
}

// 7. Secure Isolation Vault (Quarantine)
async function loadQuarantine() {
    try {
        const res = await fetch('/api/quarantine');
        const list = await res.json();
        
        const tbody = document.getElementById('quarantine-list');
        tbody.innerHTML = '';

        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-table">Secure vault is empty. No threats isolated.</td></tr>`;
            return;
        }

        list.forEach(q => {
            const tr = document.createElement('tr');
            const dateStr = new Date(q.quarantined_at).toLocaleString();
            
            tr.innerHTML = `
                <td class="threat-row-name">${q.threat_name}</td>
                <td><div class="threat-row-path" title="${q.original_path}">${q.original_path}</div></td>
                <td>${dateStr}</td>
                <td class="table-actions">
                    <button class="btn btn-accent" onclick="restoreQuarantine(${q.id})">Restore</button>
                    <button class="btn btn-danger" onclick="deleteQuarantine(${q.id})">Purge</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error(e);
    }
}

async function restoreQuarantine(id) {
    const res = await fetch(`/api/quarantine/${id}/restore`, { method: 'POST' });
    if (res.ok) {
        loadQuarantine();
        loadThreats();
        loadDashboardStats();
    }
}

async function deleteQuarantine(id) {
    if (!confirm('Permanently purge this item from disk/vault? This action is irreversible!')) return;
    const res = await fetch(`/api/quarantine/${id}/delete`, { method: 'POST' });
    if (res.ok) {
        loadQuarantine();
        loadDashboardStats();
    }
}

async function purgeQuarantine() {
    if (!confirm('Purge all vault files older than 30 days?')) return;
    await fetch('/api/quarantine/purge', { method: 'POST' });
    loadQuarantine();
    loadDashboardStats();
}

// 8. Logs and History
async function loadHistory() {
    try {
        const res = await fetch('/api/history');
        const list = await res.json();
        
        const tbody = document.getElementById('history-list');
        tbody.innerHTML = '';

        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-table">No scan histories found. Perform a scan to build logs.</td></tr>`;
            return;
        }

        list.forEach(h => {
            const tr = document.createElement('tr');
            const dateStr = new Date(h.start_time).toLocaleString();
            const duration = h.end_time ? `${Math.round(new Date(h.end_time) - new Date(h.start_time)) / 1000}s` : 'In Progress';
            
            tr.innerHTML = `
                <td><strong>${h.scan_type.toUpperCase()}</strong></td>
                <td>${dateStr}</td>
                <td>${duration}</td>
                <td>${h.files_scanned.toLocaleString()}</td>
                <td class="${h.threats_found > 0 ? 'threat-row-name' : ''}">${h.threats_found} threats</td>
                <td><span class="pulse-indicator" style="background: transparent; border: none; font-weight:700;">${h.status.toUpperCase()}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error(e);
    }
}

// 9. Performance Optimizer Core
async function runOptimizerScan() {
    document.getElementById('opt-junk-val').innerText = 'Scanning...';
    document.getElementById('opt-reg-val').innerText = 'Scanning...';
    
    try {
        const res = await fetch('/api/optimizer/scan');
        const data = await res.json();
        
        document.getElementById('opt-junk-val').innerText = data.junk_size;
        document.getElementById('opt-reg-val').innerText = `${data.broken_registries} Items`;
    } catch (e) {
        document.getElementById('opt-junk-val').innerText = 'Error';
        document.getElementById('opt-reg-val').innerText = 'Error';
    }
}

async function runOptimization() {
    const temp = document.getElementById('chk-temp').checked;
    const reg = document.getElementById('chk-reg').checked;
    const logs = document.getElementById('chk-logs').checked;
    
    if (!temp && !reg && !logs) return alert('Please check at least one optimization target class!');

    const boostRing = document.querySelector('.boost-ring');
    const boostPercent = document.querySelector('.boost-percent');
    
    boostRing.style.borderTopColor = 'var(--success)';
    boostPercent.innerText = 'CLEANING';
    
    try {
        const res = await fetch('/api/optimizer/clean', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ temp, reg, logs })
        });
        const r = await res.json();
        
        setTimeout(() => {
            boostPercent.innerText = 'BOOSTED';
            alert(`Optimization complete!\n${r.message}`);
            runOptimizerScan();
            loadDashboardStats();
        }, 1500);
    } catch (e) {
        boostPercent.innerText = 'FAILED';
        alert('Server optimization request failed');
    }
}

// 10. Engine Config Settings
async function loadSettings() {
    try {
        const res = await fetch('/api/settings');
        const cfg = await res.json();
        
        document.getElementById('cfg-perf').checked = cfg.performance_mode;
        document.getElementById('cfg-quar').checked = cfg.auto_quarantine;
        document.getElementById('cfg-arch').checked = cfg.scan_archives;
        document.getElementById('cfg-vt-key').value = cfg.virustotal_api_key || '';
    } catch (e) {
        console.error(e);
    }
}

async function saveSettings() {
    const payload = {
        performance_mode: document.getElementById('cfg-perf').checked,
        auto_quarantine: document.getElementById('cfg-quar').checked,
        scan_archives: document.getElementById('cfg-arch').checked,
        virustotal_api_key: document.getElementById('cfg-vt-key').value.trim()
    };
    
    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            alert('Preferences stored successfully! Elevated allocations synced.');
            loadSettings();
            loadDashboardStats();
        } else {
            alert('Settings failed to save.');
        }
    } catch (e) {
        alert('Could not update engine preferences.');
    }
}

// 11. Whitelist Management Core
async function loadWhitelist() {
    try {
        const res = await fetch('/api/whitelist');
        const rules = await res.json();
        const tbody = document.getElementById('whitelist-list');
        tbody.innerHTML = '';
        
        if (rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-table">No exclusion rules configured. Standard defense active.</td></tr>`;
            return;
        }
        
        rules.forEach(rule => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="threat-row-path" title="${rule.file_path || ''}">${rule.file_path || '<span class="text-dim">N/A (Hash Rule)</span>'}</td>
                <td style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">${rule.file_hash || '<span class="text-dim">N/A (Path Rule)</span>'}</td>
                <td style="color: var(--text-dim);">${rule.reason || 'No note added'}</td>
                <td style="font-size: 11px; font-family: 'JetBrains Mono', monospace;">${new Date(rule.added_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-cancel" onclick="removeWhitelistRule(${rule.id})">Remove</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Failed to retrieve exclusion rules directory:', e);
    }
}

async function addWhitelistRule() {
    const pathInput = document.getElementById('wl-path-input');
    const noteInput = document.getElementById('wl-note-input');
    const btn = document.getElementById('btn-add-path');
    const file_path = pathInput.value.trim();
    const note = noteInput.value.trim();
    
    if (!file_path) return alert('Please enter a folder or file path!');
    
    // Disable inputs and button to prevent double-clicks
    pathInput.disabled = true;
    noteInput.disabled = true;
    btn.disabled = true;
    const origText = btn.innerText;
    btn.innerText = 'ADDING RULE...';
    
    try {
        const res = await fetch('/api/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path, note })
        });
        const r = await res.json();
        alert(r.message || 'Exclusion rule configured successfully!');
        pathInput.value = '';
        noteInput.value = '';
        loadWhitelist();
        loadQuarantine(); // Refresh quarantine vault if matching items were auto-restored
        loadDashboardStats();
    } catch (e) {
        alert('Failed to save whitelist path rule.');
    } finally {
        pathInput.disabled = false;
        noteInput.disabled = false;
        btn.disabled = false;
        btn.innerText = origText;
    }
}

async function addHashWhitelistRule() {
    const hashInput = document.getElementById('wl-hash-input');
    const btn = document.getElementById('btn-add-hash');
    const file_hash = hashInput.value.trim();
    
    if (!file_hash || file_hash.length !== 64) {
        return alert('Please enter a valid 64-character SHA-256 hash value!');
    }
    
    // Disable inputs and button
    hashInput.disabled = true;
    btn.disabled = true;
    const origText = btn.innerText;
    btn.innerText = 'ADDING RULE...';
    
    try {
        const res = await fetch('/api/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_hash, note: 'Hash exclusion rule' })
        });
        const r = await res.json();
        alert(r.message || 'Exclusion rule configured successfully!');
        hashInput.value = '';
        loadWhitelist();
        loadQuarantine(); // Refresh quarantine vault
        loadDashboardStats();
    } catch (e) {
        alert('Failed to save whitelist hash rule.');
    } finally {
        hashInput.disabled = false;
        btn.disabled = false;
        btn.innerText = origText;
    }
}

async function removeWhitelistRule(wlId) {
    if (!confirm('Are you sure you want to delete this exclusion rule? Files in this path may be scanned/flagged again.')) return;
    
    try {
        const res = await fetch(`/api/whitelist/${wlId}`, {
            method: 'DELETE'
        });
        if (res.ok) {
            loadWhitelist();
        } else {
            alert('Failed to remove exclusion rule.');
        }
    } catch (e) {
        alert('Communication error deleting whitelist rule.');
    }
}
