// Security Monitoring Dashboard JavaScript
class SecurityDashboard {
    constructor() {
        this.eventSource = null;
        this.isEventsPaused = false;
        this.maxLiveEvents = 50;
        this.eventCount = 0;
        this.threatCount = 0;

        this.init();
    }

    init() {
        this.setupEventStream();
        this.setupNavigation();
        this.setupFormTabs();
        this.loadInitialData();
        this.checkSystemHealth();

        // Auto-refresh data every 30 seconds
        setInterval(() => {
            this.loadInitialData();
        }, 30000);

        // Check system health every 10 seconds
        setInterval(() => {
            this.checkSystemHealth();
        }, 10000);
    }

    setupEventStream() {
        try {
            this.eventSource = new EventSource('/stream/events');

            this.eventSource.onopen = () => {
                this.updateStreamStatus('online', 'Connected');
            };

            this.eventSource.onmessage = (event) => {
                if (event.data && event.data.trim() && !this.isEventsPaused) {
                    try {
                        const data = JSON.parse(event.data);
                        this.handleLiveEvent(data);
                    } catch (e) {
                        console.error('Error parsing event data:', e);
                    }
                }
            };

            this.eventSource.onerror = () => {
                this.updateStreamStatus('offline', 'Disconnected');
                // Try to reconnect after 5 seconds
                setTimeout(() => {
                    this.setupEventStream();
                }, 5000);
            };
        } catch (error) {
            console.error('Error setting up event stream:', error);
            this.updateStreamStatus('offline', 'Error');
        }
    }

    updateStreamStatus(status, text) {
        const statusElement = document.getElementById('streamStatus');
        if (statusElement) {
            statusElement.className = `status-indicator ${status}`;
            statusElement.innerHTML = `<i class="fas fa-circle"></i> ${text}`;
        }
    }

    handleLiveEvent(data) {
        this.eventCount++;
        document.getElementById('totalEvents').textContent = this.eventCount;

        if (data.injection_suspected || data.ddos_suspected) {
            this.threatCount++;
            document.getElementById('totalThreats').textContent = this.threatCount;
        }

        this.addLiveEventToFeed(data);
        this.updateMetrics();
    }

    addLiveEventToFeed(data) {
        const container = document.getElementById('liveEvents');
        const noEventsDiv = container.querySelector('.no-events');
        if (noEventsDiv) {
            noEventsDiv.remove();
        }

        const eventDiv = document.createElement('div');
        eventDiv.className = 'event-item';

        const timestamp = new Date().toLocaleTimeString();
        const threatBadge = data.injection_suspected || data.ddos_suspected ? 
            `<span class="event-badge threat">THREAT</span>` : 
            `<span class="event-badge safe">SAFE</span>`;

        const injectionBadge = data.injection_suspected ? 
            `<span class="event-badge injection">INJECTION</span>` : '';

        const ddosBadge = data.ddos_suspected ? 
            `<span class="event-badge ddos">DDOS</span>` : '';

        eventDiv.innerHTML = `
            <div class="event-header">
                <span class="event-ip">${data.source_ip || 'Unknown'}</span>
                <span class="event-time">${timestamp}</span>
            </div>
            <div class="event-details">
                <span>${data.method || 'GET'} ${data.path || '/'}</span>
                ${threatBadge}
                ${injectionBadge}
                ${ddosBadge}
            </div>
        `;

        eventDiv.addEventListener('click', () => {
            this.showEventDetails(data);
        });

        container.insertBefore(eventDiv, container.firstChild);

        // Keep only the latest events
        const events = container.querySelectorAll('.event-item');
        if (events.length > this.maxLiveEvents) {
            events[events.length - 1].remove();
        }
    }

    setupNavigation() {
        const navItems = document.querySelectorAll('.nav-item');
        const tabContents = document.querySelectorAll('.tab-content');

        navItems.forEach(item => {
            item.addEventListener('click', () => {
                const tabId = item.dataset.tab;

                // Update nav items
                navItems.forEach(nav => nav.classList.remove('active'));
                item.classList.add('active');

                // Update tab contents
                tabContents.forEach(tab => tab.classList.remove('active'));
                const targetTab = document.getElementById(tabId);
                if (targetTab) {
                    targetTab.classList.add('active');
                    this.onTabActivated(tabId);
                }
            });
        });
    }

    setupFormTabs() {
        const formTabs = document.querySelectorAll('.form-tab');
        const formContents = document.querySelectorAll('.form-content');

        formTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const formId = tab.dataset.form;

                // Update tab buttons
                formTabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                // Update form contents
                formContents.forEach(content => content.classList.remove('active'));
                const targetForm = document.getElementById(formId + 'Form');
                if (targetForm) {
                    targetForm.classList.add('active');
                }
            });
        });
    }

    onTabActivated(tabId) {
        switch(tabId) {
            case 'events':
                this.loadEvents();
                break;
            case 'alerts':
                this.loadAlerts();
                break;
            case 'whitelist':
                this.loadWhitelist();
                break;
            case 'analytics':
                this.loadAnalytics();
                break;
        }
    }

    async loadInitialData() {
        await this.updateMetrics();
    }

    async updateMetrics() {
        try {
            const [ddosAlerts, injectionAlerts, whitelist] = await Promise.all([
                fetch('/alerts/ddos').then(r => r.json()),
                fetch('/alerts/injection').then(r => r.json()),
                fetch('/whitelist').then(r => r.json())
            ]);

            document.getElementById('ddosCount').textContent = ddosAlerts.length || 0;
            document.getElementById('injectionCount').textContent = injectionAlerts.length || 0;
            document.getElementById('whitelistCount').textContent = 
                (whitelist.ip_count || 0) + (whitelist.pattern_count || 0);
        } catch (error) {
            console.error('Error updating metrics:', error);
        }
    }

    async checkSystemHealth() {
        try {
            const response = await fetch('/health');
            if (response.ok) {
                const data = await response.json();
                document.getElementById('apiStatus').innerHTML = 
                    '<i class="fas fa-circle"></i> Online';
                document.getElementById('apiStatus').className = 'status-indicator online';
            } else {
                throw new Error('Health check failed');
            }
        } catch (error) {
            document.getElementById('apiStatus').innerHTML = 
                '<i class="fas fa-circle"></i> Offline';
            document.getElementById('apiStatus').className = 'status-indicator offline';
        }
    }

    async loadEvents() {
        const tbody = document.getElementById('eventsTableBody');
        tbody.innerHTML = '<tr><td colspan="7" class="loading"><i class="fas fa-spinner fa-spin"></i> Loading events...</td></tr>';

        try {
            const response = await fetch('/events');
            const events = await response.json();

            if (events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center">No events found</td></tr>';
                return;
            }

            tbody.innerHTML = events.map(event => {
                const timestamp = new Date(event.timestamp || Date.now()).toLocaleString();
                const whitelistedBadge = event.whitelisted ? 
                    '<span class="event-badge safe">YES</span>' : 
                    '<span class="event-badge">NO</span>';

                return `
                    <tr onclick="showEventDetails(${JSON.stringify(event).replace(/"/g, '&quot;')})">
                        <td>${timestamp}</td>
                        <td class="font-mono">${event.source_ip || 'Unknown'}</td>
                        <td>${event.method || 'GET'}</td>
                        <td class="truncate" title="${event.path || '/'}">${event.path || '/'}</td>
                        <td>${event.country || '-'}</td>
                        <td>${whitelistedBadge}</td>
                        <td><button class="btn btn-sm" onclick="event.stopPropagation(); showEventDetails(${JSON.stringify(event).replace(/"/g, '&quot;')})">View</button></td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            console.error('Error loading events:', error);
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-red">Error loading events</td></tr>';
        }
    }

    async loadAlerts() {
        try {
            const [ddosAlerts, injectionAlerts] = await Promise.all([
                fetch('/alerts/ddos').then(r => r.json()),
                fetch('/alerts/injection').then(r => r.json())
            ]);

            this.displayAlerts('ddosAlerts', 'ddosAlertCount', ddosAlerts);
            this.displayAlerts('injectionAlerts', 'injectionAlertCount', injectionAlerts);
        } catch (error) {
            console.error('Error loading alerts:', error);
        }
    }

    displayAlerts(containerId, countId, alerts) {
        const container = document.getElementById(containerId);
        const countElement = document.getElementById(countId);

        countElement.textContent = alerts.length;

        if (alerts.length === 0) {
            container.innerHTML = '<div class="no-alerts">No alerts</div>';
            return;
        }

        container.innerHTML = alerts.map(alert => {
            const timestamp = new Date(alert.timestamp || Date.now()).toLocaleString();
            const severity = alert.severity || 'medium';

            return `
                <div class="alert-item ${severity}">
                    <div class="alert-header">
                        <strong>${alert.source_ip || 'Unknown IP'}</strong>
                        <span class="text-${severity === 'high' ? 'red' : severity === 'medium' ? 'yellow' : 'blue'}">${severity.toUpperCase()}</span>
                    </div>
                    <div class="alert-details">
                        <p><strong>Reason:</strong> ${alert.reason || 'Unknown'}</p>
                        <p><strong>Path:</strong> ${alert.path || 'N/A'}</p>
                        <p><strong>Confidence:</strong> ${((alert.confidence || 0) * 100).toFixed(1)}%</p>
                        <p><strong>Time:</strong> ${timestamp}</p>
                    </div>
                </div>
            `;
        }).join('');
    }

    async loadWhitelist() {
        const container = document.getElementById('whitelistContainer');
        container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading whitelist...</div>';

        try {
            const response = await fetch('/whitelist');
            const data = await response.json();

            const items = [
                ...(data.ip_whitelist || []).map(item => ({...item, type: 'IP'})),
                ...(data.pattern_whitelist || []).map(item => ({...item, type: 'Pattern'}))
            ];

            if (items.length === 0) {
                container.innerHTML = '<div class="no-alerts">No whitelist entries</div>';
                return;
            }

            container.innerHTML = items.map(item => `
                <div class="whitelist-item">
                    <div class="whitelist-info">
                        <div class="whitelist-value">
                            <span class="event-badge">${item.type}</span>
                            ${item.value || item.ip || item.pattern}
                        </div>
                        <div class="whitelist-reason">${item.reason || 'No reason provided'}</div>
                    </div>
                    <div class="whitelist-actions">
                        <button class="btn btn-sm btn-remove" onclick="removeWhitelistEntry('${item.value || item.ip || item.pattern}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            console.error('Error loading whitelist:', error);
            container.innerHTML = '<div class="text-center text-red">Error loading whitelist</div>';
        }
    }

    async loadAnalytics() {
        try {
            const [injectionAnalytics, ddosAnalytics] = await Promise.all([
                fetch('/analytics/injection').then(r => r.json()),
                fetch('/analytics/ddos').then(r => r.json())
            ]);

            this.displayAnalytics('injectionAnalytics', injectionAnalytics);
            this.displayAnalytics('ddosAnalytics', ddosAnalytics);
        } catch (error) {
            console.error('Error loading analytics:', error);
        }
    }

    displayAnalytics(containerId, data) {
        const container = document.getElementById(containerId);

        const stats = Object.entries(data).map(([key, value]) => {
            const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            let formattedValue = value;

            if (typeof value === 'number') {
                formattedValue = value.toLocaleString();
            } else if (typeof value === 'boolean') {
                formattedValue = value ? 'Yes' : 'No';
            }

            return `
                <div class="analytics-stat">
                    <span class="stat-name">${formattedKey}</span>
                    <span class="stat-value">${formattedValue}</span>
                </div>
            `;
        });

        container.innerHTML = stats.join('');
    }

    showEventDetails(event) {
        const modal = document.getElementById('eventModal');
        const modalBody = document.getElementById('eventModalBody');

        const details = Object.entries(event).map(([key, value]) => {
            const formattedKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            let formattedValue = value;

            if (typeof value === 'object' && value !== null) {
                formattedValue = JSON.stringify(value, null, 2);
            }

            return `
                <div class="analysis-detail">
                    <span class="detail-label">${formattedKey}:</span>
                    <span class="detail-value ${typeof value === 'object' ? 'font-mono' : ''}">${formattedValue}</span>
                </div>
            `;
        });

        modalBody.innerHTML = `<div class="analysis-result">${details.join('')}</div>`;
        modal.style.display = 'block';
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div>${message}</div>
        `;

        const container = document.getElementById('toastContainer');
        container.appendChild(toast);

        setTimeout(() => {
            toast.remove();
        }, 5000);
    }
}

// Global functions
function refreshMetrics() {
    dashboard.updateMetrics();
}

function clearEventsFeed() {
    const container = document.getElementById('liveEvents');
    container.innerHTML = `
        <div class="no-events">
            <i class="fas fa-satellite-dish"></i>
            <p>Waiting for events...</p>
        </div>
    `;
}

function toggleEventsPause() {
    dashboard.isEventsPaused = !dashboard.isEventsPaused;
    const btn = document.getElementById('pauseBtn');

    if (dashboard.isEventsPaused) {
        btn.innerHTML = '<i class="fas fa-play"></i> Resume';
    } else {
        btn.innerHTML = '<i class="fas fa-pause"></i> Pause';
    }
}

function loadEvents() {
    dashboard.loadEvents();
}

function loadWhitelist() {
    dashboard.loadWhitelist();
}

async function addIPWhitelist() {
    const ip = document.getElementById('whitelistIP').value;
    const reason = document.getElementById('whitelistIPReason').value;
    const confidence = parseFloat(document.getElementById('whitelistIPConfidence').value);

    if (!ip) {
        dashboard.showToast('IP address is required', 'error');
        return;
    }

    try {
        const response = await fetch('/whitelist/ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason, confidence })
        });

        if (response.ok) {
            dashboard.showToast('IP added to whitelist successfully', 'success');
            document.getElementById('whitelistIP').value = '';
            document.getElementById('whitelistIPReason').value = '';
            document.getElementById('whitelistIPConfidence').value = '1.0';
            dashboard.loadWhitelist();
        } else {
            const error = await response.json();
            dashboard.showToast(error.error || 'Failed to add IP to whitelist', 'error');
        }
    } catch (error) {
        dashboard.showToast('Error adding IP to whitelist', 'error');
    }
}

async function addPatternWhitelist() {
    const pattern = document.getElementById('whitelistPattern').value;
    const reason = document.getElementById('whitelistPatternReason').value;
    const confidence = parseFloat(document.getElementById('whitelistPatternConfidence').value);

    if (!pattern) {
        dashboard.showToast('Pattern is required', 'error');
        return;
    }

    try {
        const response = await fetch('/whitelist/pattern', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern, reason, confidence })
        });

        if (response.ok) {
            dashboard.showToast('Pattern added to whitelist successfully', 'success');
            document.getElementById('whitelistPattern').value = '';
            document.getElementById('whitelistPatternReason').value = '';
            document.getElementById('whitelistPatternConfidence').value = '1.0';
            dashboard.loadWhitelist();
        } else {
            const error = await response.json();
            dashboard.showToast(error.error || 'Failed to add pattern to whitelist', 'error');
        }
    } catch (error) {
        dashboard.showToast('Error adding pattern to whitelist', 'error');
    }
}

async function removeWhitelistEntry(value) {
    if (!confirm(`Are you sure you want to remove "${value}" from the whitelist?`)) {
        return;
    }

    try {
        const response = await fetch(`/whitelist/${encodeURIComponent(value)}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            dashboard.showToast('Whitelist entry removed successfully', 'success');
            dashboard.loadWhitelist();
        } else {
            const error = await response.json();
            dashboard.showToast(error.error || 'Failed to remove whitelist entry', 'error');
        }
    } catch (error) {
        dashboard.showToast('Error removing whitelist entry', 'error');
    }
}

async function analyzeRequest() {
    const data = {
        source_ip: document.getElementById('testIP').value || '127.0.0.1',
        path: document.getElementById('testPath').value || '/',
        method: document.getElementById('testMethod').value,
        body: document.getElementById('testBody').value || '',
        user_agent: document.getElementById('testUserAgent').value || 'Test-Agent/1.0',
        country: document.getElementById('testCountry').value || 'XX'
    };

    const resultsContainer = document.getElementById('analysisResults');
    resultsContainer.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Analyzing request...</div>';

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            const result = await response.json();
            displayAnalysisResults(result);
        } else {
            resultsContainer.innerHTML = '<div class="text-center text-red">Error analyzing request</div>';
        }
    } catch (error) {
        console.error('Analysis error:', error);
        resultsContainer.innerHTML = '<div class="text-center text-red">Network error during analysis</div>';
    }
}

function displayAnalysisResults(result) {
    const container = document.getElementById('analysisResults');

    const whitelistStatus = result.whitelisted ? 
        '<span class="detail-value safe">YES</span>' : 
        '<span class="detail-value">NO</span>';

    const ddosThreat = result.ddos_analysis?.confidence > 0.5 ? 
        '<span class="detail-value threat">HIGH RISK</span>' : 
        '<span class="detail-value safe">LOW RISK</span>';

    const injectionThreat = Math.max(
        result.injection_analysis?.path?.confidence || 0,
        result.injection_analysis?.body?.confidence || 0
    ) > 0.5 ? '<span class="detail-value threat">DETECTED</span>' : 
        '<span class="detail-value safe">CLEAN</span>';

    container.innerHTML = `
        <div class="analysis-result">
            <div class="analysis-title">Security Analysis Results</div>
            <div class="analysis-detail">
                <span class="detail-label">Whitelisted:</span>
                ${whitelistStatus}
            </div>
            <div class="analysis-detail">
                <span class="detail-label">DDoS Risk:</span>
                ${ddosThreat}
            </div>
            <div class="analysis-detail">
                <span class="detail-label">Injection Detection:</span>
                ${injectionThreat}
            </div>
            <div class="analysis-detail">
                <span class="detail-label">Anomaly Score:</span>
                <span class="detail-value">${result.anomaly_score !== null ? (result.anomaly_score * 100).toFixed(1) + '%' : 'N/A'}</span>
            </div>
        </div>

        <div class="analysis-result">
            <div class="analysis-title">DDoS Analysis Details</div>
            ${Object.entries(result.ddos_analysis || {}).map(([key, value]) => `
                <div class="analysis-detail">
                    <span class="detail-label">${key.replace(/_/g, ' ')}:</span>
                    <span class="detail-value">${typeof value === 'object' ? JSON.stringify(value) : value}</span>
                </div>
            `).join('')}
        </div>

        <div class="analysis-result">
            <div class="analysis-title">Injection Analysis Details</div>
            <div class="analysis-detail">
                <span class="detail-label">Path Analysis:</span>
                <span class="detail-value">${result.injection_analysis?.path?.has_injection ? 'INJECTION DETECTED' : 'Clean'}</span>
            </div>
            <div class="analysis-detail">
                <span class="detail-label">Body Analysis:</span>
                <span class="detail-value">${result.injection_analysis?.body?.has_injection ? 'INJECTION DETECTED' : 'Clean'}</span>
            </div>
        </div>
    `;
}

function showEventDetails(event) {
    dashboard.showEventDetails(event);
}

function closeModal() {
    document.getElementById('eventModal').style.display = 'none';
}

// Click outside modal to close
window.onclick = function(event) {
    const modal = document.getElementById('eventModal');
    if (event.target === modal) {
        modal.style.display = 'none';
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    window.dashboard = new SecurityDashboard();
});
