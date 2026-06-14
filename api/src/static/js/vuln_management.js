let allVulnerabilities = [];

async function fetchVulnerabilities(projectId) {
  try {
    const response = await fetch(`/api/v1/vuln/list/${projectId}`);
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const data = await response.json();

    const severityOrder = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };

    data.sort((a, b) => {
      const severityA = severityOrder[a.severity?.toLowerCase()] || 0;
      const severityB = severityOrder[b.severity?.toLowerCase()] || 0;
      return severityB - severityA;
    });

    allVulnerabilities = data;
    applyFilters();
  } catch (error) {
    console.error("Failed to fetch vulnerabilities:", error);
  }
}

function getSeverityClass(severity) {
  return `badge badge--sev-${severity.toLowerCase()}`;
}

function getStatusClass(status) {
  return `badge badge--stat-${status.toLowerCase()}`;
}

function formatStatusLabel(status) {
  return status.replace(/_/g, " ").toUpperCase();
}

function truncateSnippet(text, maxLen = 40) {
  if (!text || text === "no info") return "-";
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen)}…`;
}

function getSelectedIds() {
  return Array.from(
    document.querySelectorAll("#vuln-table tbody input[type='checkbox']:checked")
  )
    .map((checkbox) => checkbox.dataset.vulnId)
    .filter(Boolean);
}

function renderTable(data, { resetPage = false } = {}) {
  const tbody = document.getElementById("table-body");
  if (!tbody) {
    console.error("Missing table body element.");
    return;
  }

  tbody.innerHTML = "";

  if (data.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="table-empty">No vulnerabilities found.</td>
      </tr>
    `;
    window.vcRefreshTable?.("vuln-table", { resetPage: true });
    return;
  }

  data.forEach((vuln) => {
    const row = document.createElement("tr");
    const severityClass = getSeverityClass(vuln.severity);
    const statusClass = getStatusClass(vuln.status);
    const snippet = truncateSnippet(vuln.code_snippet);
    const controlType = vuln.control_type?.toUpperCase() || "-";
    const detailsUrl = `/api/v1/vuln/details/${vuln.id}`;

    row.innerHTML = `
      <td class="col-select">
        <input type="checkbox" class="vuln-checkbox" data-vuln-id="${vuln.id}" aria-label="Select vulnerability" />
      </td>
      <td><span class="${severityClass}">${vuln.severity.toUpperCase()}</span></td>
      <td><span class="${statusClass}">${formatStatusLabel(vuln.status)}</span></td>
      <td class="mono">${controlType}</td>
      <td class="vuln-snippet mono" title="${vuln.code_snippet === "no info" ? "" : vuln.code_snippet}">${snippet}</td>
      <td class="col-actions">
        <a href="${detailsUrl}" class="btn btn--outline btn--sm vuln-open-btn">Open</a>
      </td>
    `;

    row.querySelector(".vuln-open-btn")?.addEventListener("click", () => {
      localStorage.setItem("vuln_referrer", window.location.pathname);
    });

    tbody.appendChild(row);
  });

  window.vcRefreshTable?.("vuln-table", { resetPage });
}

function applyFilters() {
  const status = document.getElementById("status-filter")?.value || "";
  const severity = document.getElementById("severity-filter")?.value || "";
  const sortCreatedAt = document.getElementById("sort-created-at")?.value || "asc";
  const sortClosedAt = document.getElementById("sort-closed-at")?.value || "asc";

  let filtered = allVulnerabilities.filter((vuln) => {
    const statusMatch = status ? vuln.status.toLowerCase() === status : true;
    const severityMatch = severity ? vuln.severity.toLowerCase() === severity : true;
    return statusMatch && severityMatch;
  });

  if (sortCreatedAt) {
    filtered.sort((a, b) => {
      const dateA = new Date(a.created_at);
      const dateB = new Date(b.created_at);
      if (isNaN(dateA)) return 1;
      if (isNaN(dateB)) return -1;
      return sortCreatedAt === "asc" ? dateA - dateB : dateB - dateA;
    });
  }

  if (sortClosedAt) {
    filtered.sort((a, b) => {
      const dateA = new Date(a.closed_at);
      const dateB = new Date(b.closed_at);
      if (isNaN(dateA)) return 1;
      if (isNaN(dateB)) return -1;
      return sortClosedAt === "asc" ? dateA - dateB : dateB - dateA;
    });
  }

  renderTable(filtered, { resetPage: true });
}

document.addEventListener("DOMContentLoaded", () => {
  const projectId = document.body.dataset.projectId;
  if (projectId) {
    fetchVulnerabilities(projectId);
    document.getElementById("status-filter")?.addEventListener("change", applyFilters);
    document.getElementById("severity-filter")?.addEventListener("change", applyFilters);
  } else {
    console.warn("Project ID not found in <body data-project-id='...'>");
  }
});

let allSelected = false;

function toggleSelectAllCheckboxes() {
  const checkboxes = document.querySelectorAll("#vuln-table tbody input[type='checkbox']");
  allSelected = !allSelected;

  checkboxes.forEach((checkbox) => {
    checkbox.checked = allSelected;
  });

  const btn = document.getElementById("select-all-btn");
  if (btn) {
    btn.textContent = allSelected ? "Clear selection" : "Select All";
  }
}

const falsePositiveForm = document.getElementById("false-positive-form");

document.getElementById("ticket-btn")?.addEventListener("click", () => {
  const selectedIds = getSelectedIds();

  if (selectedIds.length === 0) {
    alert("Please select at least one vulnerability before marking as False Positive.");
    return;
  }

  falsePositiveForm.style.display = "flex";
});

document.getElementById("cancel-fp")?.addEventListener("click", () => {
  falsePositiveForm.style.display = "none";
});

falsePositiveForm?.addEventListener("click", (event) => {
  if (event.target === falsePositiveForm) {
    falsePositiveForm.style.display = "none";
  }
});

document.getElementById("submit-fp")?.addEventListener("click", async () => {
  const comment = document.getElementById("false-positive-comment").value.trim();
  const selectedIds = getSelectedIds();

  if (!comment) {
    alert("Please enter a comment.");
    return;
  }

  if (selectedIds.length === 0) {
    alert("Please select at least one vulnerability.");
    return;
  }

  try {
    await fetch("/api/v1/vuln/false_positive", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(selectedIds),
    });

    document.getElementById("false-positive-form").style.display = "none";
    document.getElementById("false-positive-comment").value = "";

    const projectId = document.body.dataset.projectId;
    if (projectId) {
      fetchVulnerabilities(projectId);
    }
  } catch (err) {
    console.error("Error:", err);
    alert("Something went wrong while submitting.");
  }
});

document.getElementById("select-all-btn")?.addEventListener("click", toggleSelectAllCheckboxes);
document.getElementById("sort-created-at")?.addEventListener("change", applyFilters);
document.getElementById("sort-closed-at")?.addEventListener("change", applyFilters);
