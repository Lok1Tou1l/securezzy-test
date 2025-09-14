const API = 'http://127.0.0.1:5000';
const STREAM = `${API}/stream/events`;

async function fetchEvents() {
  const res = await fetch(`${API}/events`);
  if (!res.ok) throw new Error('Failed to fetch events');
  return res.json();
}

async function sendSample() {
  const res = await fetch(`${API}/events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source_ip: '127.0.0.1',
      path: "/login?u=admin' OR '1'='1",
      method: 'POST',
      body: "username=admin' OR '1'='1",
    }),
  });
  return res.json();
}

function renderEvents(events) {
  const tbody = document.querySelector('#events tbody');
  tbody.innerHTML = '';
  for (const e of events) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${e.source_ip || ''}</td>
      <td>${e.method || ''}</td>
      <td>${e.path || ''}</td>
      <td>${e.body || ''}</td>
    `;
    tbody.appendChild(tr);
  }
}

function alertBanner(text, kind = 'warn') {
  const wrap = document.getElementById('alerts');
  const div = document.createElement('div');
  div.className = `alert ${kind}`;
  div.textContent = text;
  wrap.prepend(div);
  setTimeout(() => div.remove(), 5000);
}

document.getElementById('refresh').addEventListener('click', async () => {
  try {
    const events = await fetchEvents();
    renderEvents(events);
  } catch (e) {
    alertBanner('Failed to load events', 'danger');
  }
});

document.getElementById('seed').addEventListener('click', async () => {
  try {
    const result = await sendSample();
    if (result.injection_suspected || result.ddos_suspected) {
      alertBanner(`Alert: ${JSON.stringify(result)}`, 'danger');
    } else {
      alertBanner('Event stored');
    }
    const events = await fetchEvents();
    renderEvents(events);
  } catch (e) {
    alertBanner('Failed to send sample', 'danger');
  }
});

// Auto-load on startup
(async () => {
  try {
    const events = await fetchEvents();
    renderEvents(events);
  } catch (e) {
    // ignore
  }
  // Start realtime stream
  try {
    const es = new EventSource(STREAM);
    let count = 0;
    let inj = 0;
    let dd = 0;
    const list = document.getElementById('live-list');
    const elCount = document.getElementById('live-count');
    const elInj = document.getElementById('live-injection');
    const elDd = document.getElementById('live-ddos');

    es.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data && data.type === 'event') {
          count += 1;
          if (data.injection_suspected) inj += 1;
          if (data.ddos_suspected) dd += 1;
          elCount.textContent = String(count);
          elInj.textContent = String(inj);
          elDd.textContent = String(dd);

          const li = document.createElement('li');
          li.textContent = `${data.source_ip} ${data.method} ${data.path}`;
          list.prepend(li);
          while (list.children.length > 20) list.removeChild(list.lastChild);
        }
      } catch (e) {
        // ignore malformed message
      }
    };
  } catch (e) {
    // SSE not available
  }
})();


