/**
 * SCAMSHIELD AI - Risk Gauge & Metric Rendering
 */

const RiskVisualizer = {
  renderGauge(score) {
    const gaugeEl = document.getElementById("risk-gauge-score");
    const labelEl = document.getElementById("risk-verdict-label");
    const descEl = document.getElementById("risk-verdict-desc");
    const circleEl = document.getElementById("gauge-progress-circle");

    if (!gaugeEl) return;

    gaugeEl.textContent = score;

    // Circumference for r=58 is 2 * PI * 58 ≈ 364.4
    const circumference = 364.4;
    const offset = circumference - (score / 100) * circumference;
    if (circleEl) {
      circleEl.style.strokeDashoffset = offset;
    }

    if (score >= 75) {
      labelEl.className = "risk-verdict-badge verdict-high";
      labelEl.textContent = "CRITICAL RISK";
      descEl.textContent = "High probability of manipulative or fraudulent intent detected. Do NOT proceed.";
      if (circleEl) circleEl.style.stroke = "var(--status-danger)";
    } else if (score >= 40) {
      labelEl.className = "risk-verdict-badge verdict-medium";
      labelEl.textContent = "MODERATE SUSPICION";
      descEl.textContent = "Unusual patterns or urgency cues detected. Exercise caution.";
      if (circleEl) circleEl.style.stroke = "var(--status-warning)";
    } else {
      labelEl.className = "risk-verdict-badge verdict-low";
      labelEl.textContent = "LOW RISK";
      descEl.textContent = "Standard benign pattern observed. No manipulation signals found.";
      if (circleEl) circleEl.style.stroke = "var(--status-safe)";
    }
  }
};

if (typeof window !== "undefined") {
  window.RiskVisualizer = RiskVisualizer;
}
