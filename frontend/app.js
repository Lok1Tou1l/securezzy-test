const API = 'http://127.0.0.1:5000';
const STREAM = `${API}/stream/events`;

let events = [];
let filteredEvents = [];
let currentPage = 1;
let eventsPerPage = 50;
let sortColumn = 'timestamp';
let sortDirection = 'desc';
let autoRefresh = true;
let startTime = Date.now();

// Theme management
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon();
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  updateThemeIcon();
}

function updateThemeIcon() {
  const theme = document.documentElement.getAttribute('data-theme');
  const icon = document.querySelector('#theme-toggle i');
  icon.className = theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
}

// API functions
async function fetchEvents() {
  const res = await fetch(`${API}/events`);
  if (!res.ok) throw new Error('Failed to fetch events');
  return res.json();
}

async function sendSample() {
  const samples = [
    {
      source_ip: '192.168.1.100',
      path: "/login?u=admin' OR '1'='1",
      method: 'POST',
      body: "username=admin' OR '1'='1"
    },
    {
      source_ip: '10.0.0.50',
      path: '/api/users',
      method: 'GET',
      body: ''
    },
    {
      source_ip: '172.16.0.25',
      path: '/upload',
      method: 'POST',
      body: '<script>alert("XSS")</script>'
    }
  ];
  
  const sample = samples[Math.floor(Math.random() * samples.length)];
  const res = await fetch(`${API}/events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...sample,
      timestamp: new Date().toISOString()
    })
  });
  return res.json();
}

// Event rendering
function renderEvents(eventsToRender = filteredEvents) {
  const tbody = document.querySelector('#events tbody');
  tbody.innerHTML = '';
  
  const startIndex = (currentPage - 1) * eventsPerPage;
  const endIndex = startIndex + eventsPerPage;
  const pageEvents = eventsToRender.slice(startIndex, endIndex);
  
  for (const e of pageEvents) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${formatTimestamp(e.timestamp)}</td>
      <td><code>${e.source_ip || 'N/A'}</code></td>
      <td><span class="method-badge ${(e.method || '').toLowerCase()}">${e.method || 'N/A'}</span></td>
      <td class="path-cell" title="${e.path || ''}">${truncateText(e.path || '', 50)}</td>
      <td class="body-cell" title="${e.body || ''}">${truncateText(e.body || '', 30)}</td>
      <td>${renderAlertBadges(e)}</td>
    `;
    
    if (e.injection_suspected || e.ddos_suspected) {
      tr.classList.add('alert-row');
    }
    
    tbody.appendChild(tr);
  }
  
  updatePagination(eventsToRender.length);
  document.getElementById('visible-count').textContent = eventsToRender.length;
}

function renderAlertBadges(event) {
  const badges = [];
  if (event.injection_suspected) {
    badges.push('<span class="badge badge-danger"><i class="fas fa-syringe"></i> SQL</span>');
  }
  if (event.ddos_suspected) {
    badges.push('<span class="badge badge-danger"><i class="fas fa-bomb"></i> DDoS</span>');
  }
  return `<div class="alert-badges">${badges.join('')}</div>`;
}

function formatTimestamp(timestamp) {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp);
  return date.toLocaleString();
}

function truncateText(text, maxLength) {
  if (!text || text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}

// Sorting and filtering
function sortEvents(column) {
  if (sortColumn === column) {
    sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
  } else {
    sortColumn = column;
    sortDirection = 'desc';
  }
  
  filteredEvents.sort((a, b) => {
    let aVal = a[column] || '';
    let bVal = b[column] || '';
    
    if (column === 'timestamp') {
      aVal = new Date(aVal).getTime();
      bVal = new Date(bVal).getTime();
    }
    
    if (sortDirection === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });
  
  updateSortIcons();
  renderEvents();
}

function updateSortIcons() {
  document.querySelectorAll('th .sort-icon').forEach(icon => {
    icon.className = 'fas fa-sort sort-icon';
  });
  
  const currentHeader = document.querySelector(`th[data-sort="${sortColumn}"]`);
  if (currentHeader) {
    currentHeader.classList.add('sorted');
    const icon = currentHeader.querySelector('.sort-icon');
    icon.className = `fas fa-sort-${sortDirection === 'asc' ? 'up' : 'down'} sort-icon`;
  }
}

function filterEvents() {
  const searchTerm = document.getElementById('search').value.toLowerCase();
  const severityFilter = document.getElementById('severity-filter').value;
  
  filteredEvents = events.filter(event => {
    const matchesSearch = !searchTerm || 
      (event.source_ip && event.source_ip.toLowerCase().includes(searchTerm)) ||
      (event.path && event.path.toLowerCase().includes(searchTerm)) ||
      (event.method && event.method.toLowerCase().includes(searchTerm)) ||
      (event.body && event.body.toLowerCase().includes(searchTerm));
    
    const matchesSeverity = !severityFilter ||
      (severityFilter === 'critical' && (event.injection_suspected || event.ddos_suspected)) ||
      (severityFilter === 'high' && event.injection_suspected) ||
      (severityFilter === 'medium' && event.ddos_suspected) ||
      (severityFilter === 'low' && !event.injection_suspected && !event.ddos_suspected);
    
    return matchesSearch && matchesSeverity;
  });
  
  currentPage = 1;
  renderEvents();
}

// Pagination
function updatePagination(totalEvents) {
  const totalPages = Math.ceil(totalEvents / eventsPerPage);
  document.getElementById('page-info').textContent = `Page ${currentPage} of ${totalPages}`;
  document.getElementById('prev-page').disabled = currentPage === 1;
  document.getElementById('next-page').disabled = currentPage === totalPages || totalPages === 0;
}

// Alerts
function showAlert(text, type = 'warning', icon = 'fas fa-info-circle') {
  const container = document.getElementById('alerts');
  const alert = document.createElement('div');
  alert.className = `alert alert-${type}`;
  alert.innerHTML = `
    <i class="${icon}"></i>
    <div class="alert-content">
      <div class="alert-text">${text}</div>
    </div>
    <button class="alert-close"><i class="fas fa-times"></i></button>
  `;
  
  container.appendChild(alert);
  
  alert.querySelector('.alert-close').addEventListener('click', () => {
    alert.remove();
  });
  
  setTimeout(() => {
    if (alert.parentNode) alert.remove();
  }, 5000);
}

// Live updates
function updateStats() {
  const now = Date.now();
  const uptime = Math.floor((now - startTime) / 1000);
  const hours = Math.floor(uptime / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = uptime % 60;
  
  document.getElementById('uptime').textContent = 
    `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}

// Export functionality
function exportEvents() {
  const csvContent = [
    ['Timestamp', 'Source IP', 'Method', 'Path', 'Body', 'Injection Suspected', 'DDoS Suspected'],
    ...filteredEvents.map(e => [
      e.timestamp || '',
      e.source_ip || '',
      e.method || '',
      e.path || '',
      e.body || '',
      e.injection_suspected ? 'Yes' : 'No',
      e.ddos_suspected ? 'Yes' : 'No'
    ])
  ].map(row => row.map(field => `"${field}"`).join(',')).join('\n');
  
  const blob = new Blob([csvContent], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `securezzy-events-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  showAlert('Events exported successfully', 'success', 'fas fa-download');
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  
  // Theme toggle
  document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
  
  // Control buttons
  document.getElementById('refresh').addEventListener('click', async () => {
    try {
      events = await fetchEvents();
      filterEvents();
      showAlert('Events refreshed', 'success', 'fas fa-sync-alt');
    } catch (e) {
      showAlert('Failed to load events', 'danger', 'fas fa-exclamation-triangle');
    }
  });
  
  document.getElementById('seed').addEventListener('click', async () => {
    try {
      const result = await sendSample();
      if (result.injection_suspected || result.ddos_suspected) {
        showAlert('Test alert generated', 'warning', 'fas fa-bug');
      } else {
        showAlert('Test event created', 'success', 'fas fa-bug');
      }
      if (autoRefresh) {
        events = await fetchEvents();
        filterEvents();
      }
    } catch (e) {
      showAlert('Failed to send test event', 'danger', 'fas fa-exclamation-triangle');
    }
  });
  
  document.getElementById('export').addEventListener('click', exportEvents);
  
  document.getElementById('clear').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all events?')) {
      events = [];
      filteredEvents = [];
      renderEvents();
      document.getElementById('live-list').innerHTML = '';
      showAlert('Events cleared', 'warning', 'fas fa-trash');
    }
  });
  
  // Auto-refresh toggle
  document.getElementById('auto-refresh-toggle').addEventListener('click', (e) => {
    autoRefresh = !autoRefresh;
    e.target.classList.toggle('active');
    e.target.innerHTML = autoRefresh ? 
      '<i class="fas fa-play"></i> Auto-refresh' : 
      '<i class="fas fa-pause"></i> Manual';
  });
  
  // Search and filter
  document.getElementById('search').addEventListener('input', filterEvents);
  document.getElementById('severity-filter').addEventListener('change', filterEvents);
  
  // Table sorting
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      sortEvents(th.dataset.sort);
    });
  });
  
  // Pagination
  document.getElementById('prev-page').addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      renderEvents();
    }
  });
  
  document.getElementById('next-page').addEventListener('click', () => {
    const totalPages = Math.ceil(filteredEvents.length / eventsPerPage);
    if (currentPage < totalPages) {
      currentPage++;
      renderEvents();
    }
  });
  
  // Initial load and real-time setup
  (async () => {
    try {
      events = await fetchEvents();
      filterEvents();
    } catch (e) {
      // ignore initial load failure
    }
    
    // Start real-time stream
    try {
      const es = new EventSource(STREAM);
      let count = 0;
      let inj = 0;
      let dd = 0;
      const list = document.getElementById('live-list');
      const status = document.getElementById('connection-status');
      const statusText = document.getElementById('connection-text');
      
      es.onopen = () => {
        status.classList.add('connected');
        statusText.textContent = 'Connected';
      };
      
      es.onerror = () => {
        status.classList.remove('connected');
        statusText.textContent = 'Disconnected';
      };
      
      es.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          if (data && data.type === 'event') {
            count += 1;
            if (data.injection_suspected) inj += 1;
            if (data.ddos_suspected) dd += 1;
            
            document.getElementById('live-count').textContent = count.toLocaleString();
            document.getElementById('live-injection').textContent = inj.toLocaleString();
            document.getElementById('live-ddos').textContent = dd.toLocaleString();
            
            const li = document.createElement('li');
            li.innerHTML = `
              <span>${data.source_ip} ${data.method} ${data.path}</span>
              <span class="event-time">${new Date().toLocaleTimeString()}</span>
            `;
            list.prepend(li);
            
            while (list.children.length > 20) {
              list.removeChild(list.lastChild);
            }
            
            if (autoRefresh) {
              events.unshift({...data, timestamp: new Date().toISOString()});
              filterEvents();
            }
            
            if (data.injection_suspected || data.ddos_suspected) {
              showAlert(
                `Security alert from ${data.source_ip}`,
                'danger',
                'fas fa-exclamation-triangle'
              );
            }
          }
        } catch (e) {
          // ignore malformed message
        }
      };
    } catch (e) {
      showAlert('Real-time monitoring unavailable', 'warning', 'fas fa-wifi');
    }
  })();
  
  // Update uptime every second
  setInterval(updateStats, 1000);
});
