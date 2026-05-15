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

    // Сортировка по severity
    data.sort((a, b) => {
      const severityA = severityOrder[a.severity?.toLowerCase()] || 0;
      const severityB = severityOrder[b.severity?.toLowerCase()] || 0;
      return severityB - severityA;
    });

    allVulnerabilities = data;  // сохраняем отсортированные данные
    applyFilters();             // применяем фильтры к отсортированным данным

  } catch (error) {
    console.error("Failed to fetch vulnerabilities:", error);
  }
}



function getSeverityClass(severity) {
  return `severity-${severity.toLowerCase()}`;
}

function getStatusClass(status) {
  return `status-${status.toLowerCase()}`;
}

function formatDate(dateStr) {
  if (!dateStr) return "-";
  const d = new Date(dateStr);
  if (isNaN(d)) return "-";
  // YYYY-MM-DD HH:mm:ss
  const pad = num => num.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function renderTable(data) {
  const tbody = document.getElementById("table-body");
  if (!tbody) {
    console.error("Missing table body element.");
    return;
  }

  tbody.innerHTML = "";

  data.forEach(vuln => {
    const row = document.createElement("tr");

    const severityClass = getSeverityClass(vuln.severity);
    const statusClass = getStatusClass(vuln.status);

    row.innerHTML = `
      <td><input type="checkbox" /></td>
      <td><a href="/api/v1/vuln/details/${vuln.id}" class="vuln-link">${vuln.id}</a></td>
      <td><span class="${severityClass}">${vuln.severity.toUpperCase()}</span></td>
      <td><span class="${statusClass}">${vuln.status.toUpperCase()}</span></td>
      <td>${formatDate(vuln.created_at)}</td>   <!-- новая колонка -->
      <td>${formatDate(vuln.closed_at)}</td>    <!-- новая колонка -->
      <td>${vuln.control_type?.toUpperCase() || '-'}</td>
      <td>${vuln.filepath === 'no info' ? '-' : vuln.filepath}</td>
      <td>${vuln.line === 'no info' ? '-' : vuln.line}</td>
      <td>${vuln.code_snippet === 'no info' ? '-' : vuln.code_snippet}</td>
    `;

    row.querySelector(".vuln-link")?.addEventListener("click", () => {
      localStorage.setItem("vuln_referrer", window.location.pathname);
    });

    tbody.appendChild(row);
  });
}


function applyFilters() {
  const status = document.getElementById("status-filter")?.value || "";
  const severity = document.getElementById("severity-filter")?.value || "";

  const sortCreatedAt = document.getElementById("sort-created-at")?.value || "asc";
  const sortClosedAt = document.getElementById("sort-closed-at")?.value || "asc";

  let filtered = allVulnerabilities.filter(vuln => {
    const statusMatch = status ? vuln.status.toLowerCase() === status : true;
    const severityMatch = severity ? vuln.severity.toLowerCase() === severity : true;
    return statusMatch && severityMatch;
  });

  // Сортируем сначала по created_at, затем по closed_at (если оба есть)
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

  renderTable(filtered);
}

document.addEventListener("DOMContentLoaded", () => {
  const projectId = document.body.dataset.projectId;
  if (projectId) {
    fetchVulnerabilities(projectId);

    // attach filter event listeners
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

  checkboxes.forEach(checkbox => {
    checkbox.checked = allSelected;
  });

  const btn = document.getElementById("select-all-btn");
  if (btn) {
    btn.textContent = allSelected ? "Clear selection" : "Select All";
    btn.classList.toggle("btn-green", !allSelected);
    btn.classList.toggle("btn-red", allSelected);
  }
}


const falsePositiveForm = document.getElementById("false-positive-form");
const commentInput = document.getElementById("false-positive-comment");

// Открытие формы
document.getElementById("ticket-btn")?.addEventListener("click", () => {
  const checkboxes = document.querySelectorAll("#vuln-table tbody input[type='checkbox']:checked");
  const selectedIds = Array.from(checkboxes).map(cb => {
    const row = cb.closest("tr");
    const idCell = row?.querySelector("td:nth-child(2)");
    return idCell?.textContent?.trim();
  }).filter(Boolean);

  if (selectedIds.length === 0) {
    alert("Please select at least one vulnerability before marking as False Positive.");
    return;
  }

  falsePositiveForm.style.display = "flex";
});

// Закрытие формы по кнопке "Cancel"
document.getElementById("cancel-fp")?.addEventListener("click", () => {
  falsePositiveForm.style.display = "none";
});

// Закрытие формы по клику вне окна
falsePositiveForm?.addEventListener("click", (event) => {
  if (event.target === falsePositiveForm) {
    falsePositiveForm.style.display = "none";
  }
});

// Сабмит формы
document.getElementById("submit-fp")?.addEventListener("click", async () => {
  const comment = document.getElementById("false-positive-comment").value.trim();

  const checkboxes = document.querySelectorAll("#vuln-table tbody input[type='checkbox']:checked");
  const selectedIds = Array.from(checkboxes).map(cb => {
    const row = cb.closest("tr");
    const idCell = row?.querySelector("td:nth-child(2)");
    return idCell?.textContent?.trim();
  }).filter(Boolean);

  if (!comment) {
    alert("Please enter a comment.");
    return;
  }

  if (selectedIds.length === 0) {
    alert("Please select at least one vulnerability.");
    return;
  }

  try {
    //  Обновляем статус уязвимостей через PUT
    await fetch("/api/v1/vuln/false_positive", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(selectedIds), // <-- массив ID в теле
    });

    document.getElementById("false-positive-form").style.display = "none";
    document.getElementById("false-positive-comment").value = "";

    // Обновляем таблицу
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
