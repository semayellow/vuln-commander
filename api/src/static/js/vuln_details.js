// === Безопасная инициализация глобального списка уязвимостей ===
const vulnIds = window.vulnIds || [];

function getVulnIdFromUrl() {
  return window.location.pathname.split("/").pop();
}

function updateCounterDisplay() {
  const counterEl = document.getElementById("vuln-counter");
  const currentIndex = window.vulnIds.indexOf(getVulnIdFromUrl());
  if (counterEl && currentIndex !== -1) {
    counterEl.textContent = `Vulnerability ${currentIndex + 1} of ${window.vulnIds.length}`;
  }
}

async function fetchVulnerabilityDetails() {
  const id = getVulnIdFromUrl();

  const response = await fetch(`/api/v1/vuln/${id}`);
  if (!response.ok) {
    document.getElementById("details-box").innerHTML = "<p>Error loading data.</p>";
    return;
  }

  const vuln = await response.json();
  renderVulnerability(vuln);
  updateCounterDisplay();
}

function renderVulnerability(vuln) {
  const detailsBox = document.getElementById("details-box");
  const metadataBox = document.getElementById("metadata-box");

  const formatDate = (value) => {
    if (!value) return "-";
    const date = new Date(value);
    return isNaN(date) ? value : date.toLocaleString();
  };

  detailsBox.innerHTML = `
    <div class="detail-row">
      <strong>Severity:</strong>
      <span class="severity ${vuln.severity.toLowerCase()}">
        ${vuln.severity.toUpperCase()}
      </span>
    </div>
    <div class="detail-row">
      <strong>Status:</strong>
      <span id="status-label" class="status ${vuln.status.toLowerCase()}">
        ${vuln.status.toUpperCase()}
      </span>
    </div>
    <div class="detail-row"><strong>Control Type:</strong> ${vuln.connector_type.toUpperCase()}</div>
    <div class="detail-row"><strong>Filepath:</strong> ${vuln.filepath}</div>
    <div class="detail-row"><strong>Line:</strong> ${vuln.line}</div>
    <div class="detail-row"><strong>Created At:</strong> ${formatDate(vuln.created_at)}</div>
    <div class="detail-row"><strong>Closed At:</strong> ${formatDate(vuln.closed_at)}</div>
    <div class="detail-row"><strong>Code Snippet:</strong>
      <pre class="code-block">${vuln.code_snippet}</pre>
    </div>
  `;

  // Metadata
  if (vuln.custom_fields && Object.keys(vuln.custom_fields).length > 0) {
    metadataBox.innerHTML = "";
    for (const [key, value] of Object.entries(vuln.custom_fields)) {
      const isUrl = key.toLowerCase().includes("url");
      const displayValue = isUrl
        ? `<a href="${value}" target="_blank" rel="noopener noreferrer">${value}</a>`
        : value;

      metadataBox.innerHTML += `
        <div class="meta-row">
          <span class="meta-key">${key}</span>
          <span class="meta-value">${displayValue}</span>
        </div>
      `;
    }
  } else {
    metadataBox.innerHTML = `<p class="no-meta">No additional metadata.</p>`;
  }
}

// Back button logic
document.getElementById("back-button")?.addEventListener("click", () => {
  const storedReferrer = localStorage.getItem("vuln_referrer");
  if (storedReferrer) {
    localStorage.removeItem("vuln_referrer");
    window.location.href = storedReferrer;
  } else {
    window.history.back();
  }
});

// === Modal logic ===
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
        "Content-Type": "application/json"
      },
      body: JSON.stringify([vulnId])
    });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    modal.style.display = "none";
    document.getElementById("false-positive-comment").value = "";

    // Обновляем статус на странице
    const statusLabel = document.getElementById("status-label");
    if (statusLabel) {
      statusLabel.textContent = "AWAITING_REVIEW";
      statusLabel.className = "status awaiting_review";
    }

  } catch (err) {
    console.error("Error submitting false positive:", err);
    alert("Failed to submit false positive.");
  }
});

// === Навигация ===
function navigateToVuln(offset) {
  const currentId = getVulnIdFromUrl();
  const idx = window.vulnIds.indexOf(currentId);
  if (idx === -1) return;

  const targetIdx = idx + offset;
  if (targetIdx >= 0 && targetIdx < window.vulnIds.length) {
    window.location.href = `${window.vulnIds[targetIdx]}`;
  }
}

document.getElementById("prev-btn")?.addEventListener("click", () => {
  navigateToVuln(-1);
});

document.getElementById("next-btn")?.addEventListener("click", () => {
  navigateToVuln(1);
});

// === Init ===
document.addEventListener("DOMContentLoaded", fetchVulnerabilityDetails);
