/**
 * SCAMSHIELD AI - Primary Dashboard & Real-Time API Controller
 * Connects UI inputs to backend POST /api/analyze for dynamic risk calculation.
 */

document.addEventListener("DOMContentLoaded", () => {
  initHealthCheck();
  initNavigation();
  initPresetDropdown();

  if (window.AnalyzerController) {
    window.AnalyzerController.init();
  }

  // Clear fields button
  const resetBtn = document.getElementById("btn-reset");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      const msgInput = document.getElementById("input-message");
      const urlInput = document.getElementById("input-url");
      const upiInput = document.getElementById("input-upi");
      const amtInput = document.getElementById("input-amount");
      const rsnInput = document.getElementById("input-reason");
      const feedbackEl = document.getElementById("scan-feedback-msg");

      if (msgInput) msgInput.value = "";
      if (urlInput) urlInput.value = "";
      if (upiInput) upiInput.value = "";
      if (amtInput) amtInput.value = "";
      if (rsnInput) rsnInput.value = "";
      if (feedbackEl) feedbackEl.style.display = "none";

      if (window.RiskVisualizer) {
        window.RiskVisualizer.renderGauge(0, "LOW RISK", "None / Cleared", "Enter message, link, or UPI ID and run scan to evaluate risk.");
      }

      const findingsContainer = document.getElementById("findings-container");
      if (findingsContainer) {
        findingsContainer.innerHTML = '<div style="color: var(--text-dim); font-size: 0.825rem; font-style: italic;">No active signals. Input data above and click "Run Pre-Payment Scan".</div>';
      }
      const whyTextEl = document.getElementById("why-flagged-text");
      if (whyTextEl) {
        whyTextEl.textContent = "Awaiting user input. The engine will evaluate psychological coercion, link spoofing, and UPI identifier risks.";
      }
      const compContainer = document.getElementById("components-analyzed-container");
      if (compContainer) compContainer.innerHTML = "";
    });
  }

  // Scan / Analyze button
  const scanBtn = document.getElementById("btn-run-scan") || document.querySelector('[data-action="analyze"]') || document.getElementById("btn-analyze");
  if (scanBtn) {
    scanBtn.addEventListener("click", () => {
      executeScan();
    });
  }

  // Initial scan of default values
  executeScan();
});

/**
 * Executes authoritative scan by calling backend POST /api/analyze
 */
async function executeScan() {
  const scanBtn = document.getElementById("btn-run-scan");
  const feedbackEl = document.getElementById("scan-feedback-msg");

  const message = (document.getElementById("input-message")?.value || "").trim();
  const url = (document.getElementById("input-url")?.value || "").trim();
  const upiId = (document.getElementById("input-upi")?.value || "").trim();
  const amount = (document.getElementById("input-amount")?.value || "").trim();
  const reason = (document.getElementById("input-reason")?.value || "").trim();

  // Validate at least one input is provided
  if (!message && !url && !upiId && !amount) {
    if (feedbackEl) {
      feedbackEl.textContent = "⚠️ Please provide at least one input (Message, URL, or UPI ID) to analyze.";
      feedbackEl.style.display = "block";
    }
    return;
  }

  if (feedbackEl) {
    feedbackEl.style.display = "none";
  }

  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<span>⏳ Analyzing Signals...</span>`;
  }

  try {
    const payload = {
      message: message || null,
      url: url || null,
      upi_id: upiId || null,
      amount: amount || null,
      payment_reason: reason || null
    };

    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.message || `HTTP ${res.status}`);
    }

    const data = await res.json();
    renderAnalysisResult(data, { message, url, upiId, amount });

  } catch (err) {
    console.error("[ScamShield] Scan failed:", err);
    if (feedbackEl) {
      feedbackEl.textContent = `❌ Scan Error: ${err.message}`;
      feedbackEl.style.display = "block";
    }
  } finally {
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <span>Analyze</span>
      `;
    }
  }
}

// Make executeScan globally available for analyzers.js
window.executeScan = executeScan;

/**
 * Renders the complete backend analysis response into the UI
 */
function renderAnalysisResult(data, inputs) {
  // 1. Update Gauge & Verdicts
  if (window.RiskVisualizer) {
    window.RiskVisualizer.renderGauge(data.risk_score, data.risk_level, data.scam_type, data.explanation);
  }

  // 2. Update Scam Type Badge
  const scamTypeBadge = document.getElementById("scam-type-badge");
  if (scamTypeBadge) {
    scamTypeBadge.textContent = data.scam_type || "Unknown/Other";
    if (data.risk_score >= 60) {
      scamTypeBadge.style.background = "rgba(239, 68, 68, 0.15)";
      scamTypeBadge.style.borderColor = "rgba(239, 68, 68, 0.4)";
      scamTypeBadge.style.color = "#fca5a5";
    } else if (data.risk_score >= 30) {
      scamTypeBadge.style.background = "rgba(245, 158, 11, 0.15)";
      scamTypeBadge.style.borderColor = "rgba(245, 158, 11, 0.4)";
      scamTypeBadge.style.color = "#fcd34d";
    } else {
      scamTypeBadge.style.background = "rgba(16, 185, 129, 0.15)";
      scamTypeBadge.style.borderColor = "rgba(16, 185, 129, 0.4)";
      scamTypeBadge.style.color = "#6ee7b7";
    }
  }

  // 3. Components Analyzed Tags
  const compContainer = document.getElementById("components-analyzed-container");
  if (compContainer) {
    compContainer.innerHTML = (data.components_analyzed || []).map(comp => {
      let icon = "🔍";
      if (comp.includes("Message")) icon = "💬";
      else if (comp.includes("URL")) icon = "🔗";
      else if (comp.includes("UPI")) icon = "💳";
      else if (comp.includes("Payment")) icon = "💰";
      return `<span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-main); font-weight: 500;">${icon} ${comp}</span>`;
    }).join("");
  }

  // 4. "Why Was This Flagged?" Narrative
  const whyTextEl = document.getElementById("why-flagged-text");
  if (whyTextEl) {
    whyTextEl.textContent = data.explanation || "No suspicious signals detected.";
    if (data.risk_score >= 60) {
      whyTextEl.style.borderLeftColor = "var(--status-danger)";
    } else if (data.risk_score >= 30) {
      whyTextEl.style.borderLeftColor = "var(--status-warning)";
    } else {
      whyTextEl.style.borderLeftColor = "var(--status-safe)";
    }
  }

  // 5. Detected Signals Breakdown with Contributions
  const findingsContainer = document.getElementById("findings-container");
  if (findingsContainer) {
    if (!data.signal_contributions || data.signal_contributions.length === 0) {
      findingsContainer.innerHTML = `
        <div class="finding-card" style="border-left: 3px solid var(--status-safe);">
          <div class="finding-icon" style="color: var(--status-safe);">✓</div>
          <div>
            <div class="finding-title" style="color: #6ee7b7;">Clean Pre-Payment Profile</div>
            <div class="finding-detail">No coercive deadlines, deceptive domain patterns, or suspicious payment requests detected.</div>
          </div>
        </div>
      `;
    } else {
      findingsContainer.innerHTML = data.signal_contributions.map(sig => {
        let icon = "⚠️";
        let badgeClass = "badge-danger";
        if (sig.severity === "CRITICAL") {
          icon = "🚨";
          badgeClass = "badge-danger";
        } else if (sig.severity === "MEDIUM" || sig.severity === "CAUTION") {
          icon = "⚡";
          badgeClass = "badge-warning";
        } else if (sig.severity === "LOW") {
          icon = "ℹ️";
          badgeClass = "badge-safe";
        }

        return `
          <div class="finding-card">
            <div class="finding-icon">${icon}</div>
            <div style="flex: 1;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.2rem;">
                <div class="finding-title">${sig.signal}</div>
                <span class="badge ${badgeClass}">${sig.weight} pts</span>
              </div>
              <div class="finding-detail">${sig.description}</div>
            </div>
          </div>
        `;
      }).join("");
    }
  }

  // 6. Recommended Action Box
  const actionBox = document.getElementById("recommended-action-box");
  if (actionBox) {
    actionBox.textContent = data.recommended_action || "Verify transaction independently through official channels.";
    if (data.risk_score >= 60) {
      actionBox.style.background = "rgba(239, 68, 68, 0.1)";
      actionBox.style.borderColor = "rgba(239, 68, 68, 0.4)";
      actionBox.style.color = "#fecaca";
    } else if (data.risk_score >= 30) {
      actionBox.style.background = "rgba(245, 158, 11, 0.1)";
      actionBox.style.borderColor = "rgba(245, 158, 11, 0.4)";
      actionBox.style.color = "#fde68a";
    } else {
      actionBox.style.background = "rgba(16, 185, 129, 0.08)";
      actionBox.style.borderColor = "rgba(16, 185, 129, 0.3)";
      actionBox.style.color = "#d1fae5";
    }
  }

  // 7. Update Disclaimer
  const disclaimerEl = document.getElementById("disclaimer-text");
  if (disclaimerEl && data.disclaimer) {
    disclaimerEl.textContent = `🛡️ ${data.disclaimer}`;
  }

  // 8. Prepend to Audit History Table
  addScanToHistory(data, inputs);
}

/**
 * Prepends a scan entry into the local audit history table
 */
function addScanToHistory(data, inputs) {
  const tbody = document.getElementById("scan-history-body");
  if (!tbody) return;

  const now = new Date();
  const timeStr = `Today, ${now.toTimeString().split(" ")[0]}`;

  let targetDesc = "Multi-Signal Scan";
  if (inputs.url) {
    targetDesc = `URL: <code>${inputs.url.substring(0, 30)}${inputs.url.length > 30 ? '...' : ''}</code>`;
  } else if (inputs.upiId) {
    targetDesc = `UPI: <code>${inputs.upiId}</code>`;
  } else if (inputs.message) {
    targetDesc = `SMS: "${inputs.message.substring(0, 25)}..."`;
  }

  let badgeClass = "badge-danger";
  if (data.risk_score < 30) badgeClass = "badge-safe";
  else if (data.risk_score < 60) badgeClass = "badge-warning";

  const row = document.createElement("tr");
  row.innerHTML = `
    <td style="font-family: var(--font-mono); color: var(--text-dim);">${timeStr}</td>
    <td>${targetDesc}</td>
    <td>${data.scam_type}</td>
    <td><span class="badge ${badgeClass}">${data.risk_level}</span></td>
    <td><span class="badge ${badgeClass}">${data.risk_score} / 100</span></td>
    <td style="color: var(--text-muted); font-size: 0.785rem;">${(data.recommended_action || "").substring(0, 75)}...</td>
  `;

  if (tbody.firstChild) {
    tbody.insertBefore(row, tbody.firstChild);
  } else {
    tbody.appendChild(row);
  }
}

/**
 * Health check: queries GET /api/health and updates UI status
 */
async function initHealthCheck() {
  const statusPill = document.getElementById("system-status-indicator");
  const statusText = document.getElementById("system-status-text");

  try {
    const res = await fetch("/api/health");
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const data = await res.json();

    if (data.status === "online" || data.system === "SYSTEM ONLINE") {
      if (statusPill) statusPill.className = "system-pill";
      if (statusText) statusText.textContent = "SYSTEM ONLINE";
    } else {
      throw new Error("Unexpected status response");
    }
  } catch (err) {
    console.warn("[ScamShield HealthCheck] Backend unreachable:", err);
    if (statusPill && statusText) {
      statusPill.className = "system-pill offline";
      statusText.textContent = "SYSTEM OFFLINE";
    }
  }
}

/**
 * Navigation handler between Dashboard, Analyze, History
 */
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      navItems.forEach(n => n.classList.remove("active"));
      item.classList.add("active");

      const targetView = item.getAttribute("data-view");
      if (targetView === "analyze") {
        document.getElementById("panel-analyze-workspace")?.scrollIntoView({ behavior: "smooth" });
      } else if (targetView === "history") {
        document.getElementById("panel-recent-scans")?.scrollIntoView({ behavior: "smooth" });
      } else {
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    });
  });
}

/**
 * Populates scenario dropdown from DEMO_PRESETS
 */
function initPresetDropdown() {
  const select = document.getElementById("demo-scenario-select");
  if (!select || !window.DEMO_PRESETS) return;

  select.innerHTML = '<option value="">-- Quick Load Simulated Scenario --</option>';
  window.DEMO_PRESETS.forEach(preset => {
    const opt = document.createElement("option");
    opt.value = preset.id;
    opt.textContent = `${preset.label} (${preset.category})`;
    select.appendChild(opt);
  });
}
