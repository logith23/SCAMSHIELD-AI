/**
 * SCAMSHIELD AI - Primary Dashboard Controller
 * Connects to GET /api/health and orchestrates UI interactions.
 */

document.addEventListener("DOMContentLoaded", () => {
  initHealthCheck();
  initNavigation();
  initPresetDropdown();
  
  if (window.AnalyzerController) {
    window.AnalyzerController.init();
  }

  // Initial gauge preview state
  if (window.RiskVisualizer) {
    window.RiskVisualizer.renderGauge(88); // Default demo state
  }

  // Action buttons
  const resetBtn = document.getElementById("btn-reset");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      document.getElementById("input-message").value = "";
      document.getElementById("input-url").value = "";
      document.getElementById("input-upi").value = "";
      document.getElementById("input-amount").value = "";
      if (window.RiskVisualizer) {
        window.RiskVisualizer.renderGauge(0);
      }
    });
  }

  const scanBtn = document.getElementById("btn-run-scan");
  if (scanBtn) {
    scanBtn.addEventListener("click", () => {
      // Step 2 foundation behavior: trigger animation and acknowledge
      scanBtn.innerHTML = `<span>⏳ Analyzing Signals...</span>`;
      setTimeout(() => {
        scanBtn.innerHTML = `<span>🛡️ Run Pre-Payment Scan</span>`;
        // Future steps will connect to actual POST /api/analyze
      }, 700);
    });
  }
});

/**
 * Health check: queries GET /api/health and updates UI to SYSTEM ONLINE
 */
async function initHealthCheck() {
  const statusPill = document.getElementById("system-status-indicator");
  const statusText = document.getElementById("system-status-text");

  try {
    const res = await fetch("/api/health");
    if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
    const data = await res.json();

    if (data.status === "online" || data.system === "SYSTEM ONLINE") {
      statusPill.className = "system-pill";
      statusText.textContent = "SYSTEM ONLINE";
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
  const views = {
    dashboard: document.getElementById("view-dashboard"),
    analyze: document.getElementById("view-analyze"),
    history: document.getElementById("view-history")
  };

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      navItems.forEach(n => n.classList.remove("active"));
      item.classList.add("active");

      const targetView = item.getAttribute("data-view");
      // Scroll smoothly to target section or switch views
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
