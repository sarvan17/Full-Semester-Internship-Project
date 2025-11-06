
const API_BASE = "http://127.0.0.1:8000";

async function loadHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error("health error");
    const data = await res.json();
    document.getElementById("health-status").innerHTML =
      `<b>Server:</b> ${data.status} | <b>Time:</b> ${new Date(data.time).toLocaleString()}`;
  } catch (err) {
    document.getElementById("health-status").innerHTML = "❌ Server offline";
  }
}

async function loadSessions() {
  const tbody = document.querySelector("#sessions-table tbody");
  tbody.innerHTML = "<tr><td colspan='8'>Loading...</td></tr>";
  try {
    const res = await fetch(`${API_BASE}/admin/sessions?active_only=false`);
    const sessions = await res.json();

    if (sessions.length === 0) {
      tbody.innerHTML = "<tr><td colspan='8'>No sessions found</td></tr>";
      return;
    }

    tbody.innerHTML = "";
    sessions.forEach(s => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${s.id}</td>
        <td>${s.username}</td>
        <td>${s.resource}</td>
        <td>${s.bits}</td>
        <td>${new Date(s.created_at).toLocaleString()}</td>
        <td>${new Date(s.expires_at).toLocaleString()}</td>
        <td>${s.used ? "✅ Yes" : "🟢 No"}</td>
        <td>${!s.used ? `<button onclick="revoke(${s.id})">Revoke</button>` : ""}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = "<tr><td colspan='8'>Error loading sessions</td></tr>";
  }
}

async function loadLogs() {
  const tbody = document.querySelector("#logs-table tbody");
  tbody.innerHTML = "<tr><td colspan='4'>Loading...</td></tr>";
  try {
    const res = await fetch(`${API_BASE}/admin/logs`);
    const logs = await res.json();
    if (logs.length === 0) {
      tbody.innerHTML = "<tr><td colspan='4'>No logs yet</td></tr>";
      return;
    }
    tbody.innerHTML = "";
    logs.forEach(log => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${log.id}</td>
        <td>${log.username}</td>
        <td>${log.resource}</td>
        <td>${new Date(log.access_time).toLocaleString()}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = "<tr><td colspan='4'>Error loading logs</td></tr>";
  }
}

async function revoke(id) {
  if (!confirm("Revoke token id " + id + "?")) return;
  try {
    const res = await fetch(`${API_BASE}/admin/revoke/${id}`, { method: "POST" });
    const data = await res.json();
    alert(`Token #${id} ${data.status}`);
  } catch (err) {
    alert("Error revoking token");
  }
  loadSessions();
}

loadHealth();
loadSessions();
loadLogs();

setInterval(loadHealth, 5000);
setInterval(loadSessions, 10000);
setInterval(loadLogs, 10000);
