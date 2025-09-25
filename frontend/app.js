class SecureDashboard {
  constructor() {
    this.API = 'http://127.0.0.1:5000';
    this.STREAM = `${this.API}/stream/events`;
    this.eventSource = null;
    this.isStreamPaused = false;
    this.events = [];
    this.filteredEvents = [];
    this.currentPage = 1;
    this.eventsPerPage = 20;
    this.stats = {
      total: 0,
      injection: 0,
      ddos: 0,
      lastUpdate: Date.now()
    };
    
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.loadEvents();
    this.startRealtimeStream();
    this.startMetricsUpdater();
  }

  setupEventListeners() {
    // Existing controls
    document.getElementById('refresh').addEventListener('click', () => this.loadEvents());
    document.getElementById('seed').addEventListener('click', () => this.sendSampleEvent());
    
    // New controls
    document.getElementById('clear-events').addEventListener('click', () => this.clearEvents());
    document.getElementById('pause-stream').addEventListener('click', () => this.toggleStream());
    
    // Filters
    document.getElementById('search-filter').addEventListener('input', (e) => this.filterEvents());
    document.getElementById('severity-filter').addEventListener('change', () => this.filterEvents());
    document.getElementById('type-filter').addEventListener('change', () => this.filterEvents());
    
    // Pagination
    document.getElementById('prev-page').addEventListener('click', () => this.prevPage());
    document.getElementById('next-page').addEventListener('click', () => this.nextPage());
    
    // Modal
    document.querySelector('.modal-close').addEventListener('click', () => this.closeModal());
    window.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal')) this.closeModal();
    });
  }

  async loadEvents() {
    try {
      const response = await fetch(`${this.API}/events`);
      if (!response.ok) throw new Error('Failed to fetch events');
      
      this.events = await response.json();
      this.events = this.events.map(event => ({
        ...event,
        timestamp: new Date(event.timestamp || Date.now()),
        threat_level: this.calculateThreatLevel(event),
        id: event.id || Math.random().toString(36).substr(2, 9)
      }));
      
      this.filterEvents();
      this.updateConnectionStatus(true);
    } catch (error) {
      this.showAlert('Failed to load events', 'danger');
      this.updateConnectionStatus(false);
    }
  }

  calculateThreatLevel(event) {
    if (event.injection_suspected && event.ddos_suspected) return 'critical';
    if (event.injection_suspected || event.ddos_suspected) return 'high';
    if (event.path && (event.path.includes('admin') || event.path.includes('login'))) return 'medium';
    return 'low';
  }

  filterEvents() {
    const searchTerm = document.getElementById('search-filter').value.toLowerCase();
    const severityFilter = document.getElementById('severity-filter').value;
    const typeFilter = document.getElementById('type-filter').value;

    this.filteredEvents = this.events.filter(event => {
      const matchesSearch = !searchTerm || 
        event.source_ip?.toLowerCase().includes(searchTerm) ||
        event.path?.toLowerCase().includes(searchTerm) ||
        event.method?.toLowerCase().includes(searchTerm);
      
      const matchesSeverity = !severityFilter || event.threat_level === severityFilter;
      
      const matchesType = !typeFilter || 
        (typeFilter === 'injection' && event.injection_suspected) ||
        (typeFilter === 'ddos' && event.ddos_suspected) ||
        (typeFilter === 'normal' && !event.injection_suspected && !event.ddos_suspected);

      return matchesSearch && matchesSeverity && matchesType;
    });

    this.currentPage = 1;
    this.renderEvents();
    this.updatePagination();
  }

  renderEvents() {
    const tbody = document.querySelector('#events tbody');
    const startIndex = (this.currentPage - 1) * this.eventsPerPage;
    const endIndex = startIndex + this.eventsPerPage;
    const pageEvents = this.filteredEvents.slice(startIndex, endIndex);

    tbody.innerHTML = '';
    
    pageEvents.forEach(event => {
      const tr = document.createElement('tr');
      if (event.threat_level === 'high' || event.threat_level === 'critical') {
        tr.classList.add(`threat-${event.threat_level}`);
      }
      
      tr.innerHTML = `
        <td>${event.timestamp.toLocaleString()}</td>
        <td>${event.source_ip || 'N/A'}</td>
        <td><span class="method-badge method-${event.method?.toLowerCase()}">${event.method || 'N/A'}</span></td>
        <td class="path-cell" title="${event.path || ''}">${this.truncateText(event.path || 'N/A', 50)}</td>
        <td class="body-cell" title="${event.body || ''}">${this.truncateText(event.body || 'N/A', 30)}</td>
        <td><span class="threat-badge threat-${event.threat_level}">${event.threat_level.toUpperCase()}</span></td>
        <td>
          <button class="btn-view" onclick="dashboard.viewEventDetails('${event.id}')">View</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  truncateText(text, maxLength) {
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
  }

  updatePagination() {
    const totalPages = Math.ceil(this.filteredEvents.length / this.eventsPerPage);
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');
    const pageInfo = document.getElementById('page-info');

    prevBtn.disabled = this.currentPage === 1;
    nextBtn.disabled = this.currentPage === totalPages || totalPages === 0;
    pageInfo.textContent = `Page ${this.currentPage} of ${totalPages || 1}`;
  }

  prevPage() {
    if (this.currentPage > 1) {
      this.currentPage--;
      this.renderEvents();
      this.updatePagination();
    }
  }

  nextPage() {
    const totalPages = Math.ceil(this.filteredEvents.length / this.eventsPerPage);
    if (this.currentPage < totalPages) {
      this.currentPage++;
      this.renderEvents();
      this.updatePagination();
    }
  }

  viewEventDetails(eventId) {
    const event = this.events.find(e => e.id === eventId);
    if (!event) return;

    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = `
      <div class="event-details">
        <div class="detail-row">
          <strong>Timestamp:</strong> ${event.timestamp.toLocaleString()}
        </div>
        <div class="detail-row">
          <strong>Source IP:</strong> ${event.source_ip || 'N/A'}
        </div>
        <div class="detail-row">
          <strong>Method:</strong> ${event.method || 'N/A'}
        </div>
        <div class="detail-row">
          <strong>Path:</strong> <code>${event.path || 'N/A'}</code>
        </div>
        <div class="detail-row">
          <strong>Request Body:</strong> <pre><code>${event.body || 'N/A'}</code></pre>
        </div>
        <div class="detail-row">
          <strong>Threat Level:</strong> <span class="threat-badge threat-${event.threat_level}">${event.threat_level.toUpperCase()}</span>
        </div>
        <div class="detail-row">
          <strong>Injection Suspected:</strong> ${event.injection_suspected ? '⚠️ Yes' : '✅ No'}
        </div>
        <div class="detail-row">
          <strong>DDoS Suspected:</strong> ${event.ddos_suspected ? '⚠️ Yes' : '✅ No'}
        </div>
      </div>
    `;

    document.getElementById('event-modal').style.display = 'block';
  }

  closeModal() {
    document.getElementById('event-modal').style.display = 'none';
  }

  async sendSampleEvent() {
    try {
      const response = await fetch(`${this.API}/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_ip: '127.0.0.1',
          path: "/login?u=admin' OR '1'='1",
          method: 'POST',
          body: "username=admin' OR '1'='1",
        }),
      });

      const result = await response.json();
      
      if (result.injection_suspected || result.ddos_suspected) {
        this.showAlert(`Security Alert: ${JSON.stringify(result)}`, 'danger');
      } else {
        this.showAlert('Test event sent successfully', 'success');
      }
      
      await this.loadEvents();
    } catch (error) {
      this.showAlert('Failed to send test event', 'danger');
    }
  }

  clearEvents() {
    if (confirm('Are you sure you want to clear all events? This action cannot be undone.')) {
      // In a real implementation, this would call an API endpoint to clear events
      this.events = [];
      this.filteredEvents = [];
      this.renderEvents();
      this.updatePagination();
      this.showAlert('Events cleared successfully', 'success');
    }
  }

  startRealtimeStream() {
    try {
      this.eventSource = new EventSource(this.STREAM);
      
      this.eventSource.onopen = () => {
        this.updateConnectionStatus(true);
      };

      this.eventSource.onmessage = (evt) => {
        if (this.isStreamPaused) return;
        
        try {
          const data = JSON.parse(evt.data);
          if (data && data.type === 'event') {
            this.handleRealtimeEvent(data);
          }
        } catch (error) {
          console.warn('Failed to parse realtime event:', error);
        }
      };

      this.eventSource.onerror = () => {
        this.updateConnectionStatus(false);
      };
    } catch (error) {
      this.updateConnectionStatus(false);
      console.warn('EventSource not available');
    }
  }

  handleRealtimeEvent(data) {
    // Update stats
    this.stats.total++;
    if (data.injection_suspected) this.stats.injection++;
    if (data.ddos_suspected) this.stats.ddos++;
    
    // Add to live list
    const list = document.getElementById('live-list');
    const li = document.createElement('li');
    li.innerHTML = `
      <span>${data.source_ip} ${data.method} ${data.path}</span>
      <span class="timestamp">${new Date().toLocaleTimeString()}</span>
    `;
    
    if (data.injection_suspected || data.ddos_suspected) {
      li.classList.add('threat');
    }
    
    list.prepend(li);
    while (list.children.length > 20) {
      list.removeChild(list.lastChild);
    }
    
    // Update metrics
    this.updateMetrics();
    
    // Show alert for high-risk events
    if (data.injection_suspected || data.ddos_suspected) {
      this.showAlert(`Security threat detected from ${data.source_ip}`, 'danger');
    }
  }

  toggleStream() {
    const button = document.getElementById('pause-stream');
    this.isStreamPaused = !this.isStreamPaused;
    button.textContent = this.isStreamPaused ? 'Resume' : 'Pause';
    button.classList.toggle('paused', this.isStreamPaused);
  }

  updateConnectionStatus(connected) {
    const status = document.getElementById('connection-status');
    const text = status.querySelector('.text');
    
    if (connected) {
      status.classList.add('connected');
      text.textContent = 'Connected';
    } else {
      status.classList.remove('connected');
      text.textContent = 'Disconnected';
    }
  }

  updateMetrics() {
    document.getElementById('live-count').textContent = this.stats.total;
    document.getElementById('live-injection').textContent = this.stats.injection;
    document.getElementById('live-ddos').textContent = this.stats.ddos;
    
    // Update threat level
    const threatLevel = document.getElementById('threat-level');
    let level = 'LOW';
    let className = 'low';
    
    if (this.stats.injection > 10 || this.stats.ddos > 5) {
      level = 'CRITICAL';
      className = 'critical';
    } else if (this.stats.injection > 5 || this.stats.ddos > 2) {
      level = 'HIGH';
      className = 'high';
    } else if (this.stats.injection > 0 || this.stats.ddos > 0) {
      level = 'MEDIUM';
      className = 'medium';
    }
    
    threatLevel.textContent = level;
    threatLevel.className = `threat-level ${className}`;
  }

  startMetricsUpdater() {
    setInterval(() => {
      this.updateMetrics();
    }, 5000);
  }

  showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alerts');
    const alert = document.createElement('div');
    alert.className = `alert ${type}`;
    alert.textContent = message;
    
    alertContainer.appendChild(alert);
    
    setTimeout(() => {
      if (alert.parentNode) {
        alert.parentNode.removeChild(alert);
      }
    }, 5000);
  }
}

// Initialize dashboard
const dashboard = new SecureDashboard();
