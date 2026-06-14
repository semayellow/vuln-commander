const vulnIds = window.vulnIds || [];

function getVulnIdFromUrl() {
  return window.location.pathname.split("/").pop();
}

function updateCounterDisplay() {
  const counterEl = document.getElementById("vuln-counter");
  const currentIndex = vulnIds.indexOf(getVulnIdFromUrl());
  if (counterEl && currentIndex !== -1) {
    counterEl.textContent = `Vulnerability ${currentIndex + 1} of ${vulnIds.length}`;
  }
}

function formatDate(dateStr) {
  if (!dateStr) return "-";
  const d = new Date(dateStr);
  if (isNaN(d)) return "-";
  const pad = (num) => num.toString().padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatStatusLabel(status) {
  return status.replace(/_/g, " ").toUpperCase();
}

function severityBadgeClass(severity) {
  return `badge badge--sev-${severity.toLowerCase()}`;
}

function statusBadgeClass(status) {
  return `badge badge--stat-${status.toLowerCase()}`;
}

async function fetchVulnerabilityDetails() {
  const id = getVulnIdFromUrl();

  const response = await fetch(`/api/v1/vuln/${id}`);
  if (!response.ok) {
    document.getElementById("details-box").innerHTML = "<p class=\"vuln-no-meta\">Error loading data.</p>";
    return;
  }

  const vuln = await response.json();
  renderVulnerability(vuln);
  updateCounterDisplay();
}

function renderVulnerability(vuln) {
  const detailsBox = document.getElementById("details-box");
  const metadataBox = document.getElementById("metadata-box");

  detailsBox.innerHTML = `
    <div class="vuln-detail-row">
      <span class="vuln-detail-row__label">Severity:</span>
      <span class="${severityBadgeClass(vuln.severity)}">${vuln.severity.toUpperCase()}</span>
    </div>
    <div class="vuln-detail-row">
      <span class="vuln-detail-row__label">Status:</span>
      <span id="status-label" class="${statusBadgeClass(vuln.status)}">${formatStatusLabel(vuln.status)}</span>
    </div>
    <div class="vuln-detail-row">
      <span class="vuln-detail-row__label">Control Type:</span>
      <span class="vuln-detail-row__value">${vuln.connector_type.toUpperCase()}</span>
    </div>
    <div class="vuln-detail-row">
      <span class="vuln-detail-row__label">Filepath:</span>
      <span class="vuln-detail-row__value">${vuln.filepath}</span>
    </div>
    <div class="vuln-detail-row">
      <span class="vuln-detail-row__label">Line:</span>
      <span class="vuln-detail-row__value">${vuln.line}</span>
    </div>
    <div class="vuln-detail-row">
      <span class="vuln-detail-row__label">Created At:</span>
      <span class="vuln-detail-row__value">${formatDate(vuln.created_at)}</span>
    </div>
    <div class="vuln-detail-row">
      <span class="vuln-detail-row__label">Closed At:</span>
      <span class="vuln-detail-row__value">${formatDate(vuln.closed_at)}</span>
    </div>
    <div class="vuln-detail-row vuln-detail-row--stacked">
      <span class="vuln-detail-row__label">Code Snippet:</span>
      <pre class="vuln-code-block">${vuln.code_snippet}</pre>
    </div>
  `;

  if (vuln.custom_fields && Object.keys(vuln.custom_fields).length > 0) {
    metadataBox.innerHTML = "";
    for (const [key, value] of Object.entries(vuln.custom_fields)) {
      const isUrl = key.toLowerCase().includes("url");
      const displayValue = isUrl
        ? `<a href="${value}" target="_blank" rel="noopener noreferrer">${value}</a>`
        : value;

      metadataBox.innerHTML += `
        <div class="vuln-meta-row">
          <span class="vuln-meta-key">${key}</span>
          <span class="vuln-meta-value">${displayValue}</span>
        </div>
      `;
    }
  } else {
    metadataBox.innerHTML = `<p class="vuln-no-meta">No additional metadata.</p>`;
  }
}

document.getElementById("back-button")?.addEventListener("click", () => {
  const storedReferrer = localStorage.getItem("vuln_referrer");
  if (storedReferrer) {
    localStorage.removeItem("vuln_referrer");
    window.location.href = storedReferrer;
  } else {
    window.history.back();
  }
});

const modal = document.getElementById("false-positive-modal");
const openBtn = document.getElementById("ticket-btn");
const closeBtn = document.getElementById("cancel-fp");
const submitBtn = document.getElementById("submit-fp");

openBtn?.addEventListener("click", () => {
  modal.style.display = "flex";
});

closeBtn?.addEventListener("click", () => {
  modal.style.display = "none";
  document.getElementById("false-positive-comment").value = "";
});

modal?.addEventListener("click", (e) => {
  if (e.target === modal) {
    modal.style.display = "none";
    document.getElementById("false-positive-comment").value = "";
  }
});

submitBtn?.addEventListener("click", async () => {
  const comment = document.getElementById("false-positive-comment").value.trim();
  const vulnId = getVulnIdFromUrl();

  if (!comment) {
    alert("Please enter a comment.");
    return;
  }

  try {
    const response = await fetch("/api/v1/vuln/false_positive", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify([vulnId]),
    });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    modal.style.display = "none";
    document.getElementById("false-positive-comment").value = "";

    const statusLabel = document.getElementById("status-label");
    if (statusLabel) {
      statusLabel.textContent = "AWAITING REVIEW";
      statusLabel.className = statusBadgeClass("awaiting_review");
    }
  } catch (err) {
    console.error("Error submitting false positive:", err);
    alert("Failed to submit false positive.");
  }
});

function navigateToVuln(offset) {
  const currentId = getVulnIdFromUrl();
  const idx = vulnIds.indexOf(currentId);
  if (idx === -1) return;

  const targetIdx = idx + offset;
  if (targetIdx >= 0 && targetIdx < vulnIds.length) {
    window.location.href = `/api/v1/vuln/details/${vulnIds[targetIdx]}`;
  }
}

document.getElementById("prev-btn")?.addEventListener("click", () => {
  navigateToVuln(-1);
});

document.getElementById("next-btn")?.addEventListener("click", () => {
  navigateToVuln(1);
});

document.addEventListener("DOMContentLoaded", fetchVulnerabilityDetails);
