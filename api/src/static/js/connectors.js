(function () {
  const REFRESH_INTERVAL_MS = 60_000;
  const TABLE_ID = "connectors-table";

  function escapeHtml(text) {
    const element = document.createElement("div");
    element.textContent = text;
    return element.innerHTML;
  }

  function formatUtcTimestamp(date) {
    const pad = (value) => String(value).padStart(2, "0");
    return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
  }

  function updateLastUpdated() {
    const element = document.querySelector(`[data-table-last-updated="${TABLE_ID}"]`);
    if (!element) {
      return;
    }

    const now = new Date();
    element.textContent = formatUtcTimestamp(now);
    element.setAttribute("datetime", now.toISOString());
  }

  function renderTable(connectors) {
    const tbody = document.querySelector("#connectors-table tbody");
    if (!tbody) {
      return;
    }

    tbody.innerHTML = "";

    if (connectors.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="table-empty">No connectors registered yet.</td>
        </tr>
      `;
      window.vcRefreshTable?.(TABLE_ID);
      updateLastUpdated();
      return;
    }

    connectors.forEach((connector) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="cell-primary">${escapeHtml(connector.name)}</td>
        <td>${escapeHtml(connector.scope)}</td>
        <td><span class="${escapeHtml(connector.status_class)}">${escapeHtml(connector.status)}</span></td>
        <td>${escapeHtml(String(connector.last_run ?? "-"))}</td>
      `;
      tbody.appendChild(row);
    });

    window.vcRefreshTable?.(TABLE_ID);
    updateLastUpdated();
  }

  async function fetchConnectors() {
    try {
      const response = await fetch("/api/v1/connectors/list", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      const data = await response.json();
      renderTable(data);
    } catch (error) {
      console.error("Failed to fetch connectors:", error);
    }
  }

  function init() {
    updateLastUpdated();
    fetchConnectors();
    setInterval(fetchConnectors, REFRESH_INTERVAL_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
