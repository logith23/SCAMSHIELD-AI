/**
 * SCAMSHIELD AI - Risk Gauge & Metric Rendering
 * Accurately animates circular SVG progress gauge and updates verdict badges.
 */

const RiskVisualizer = {
  renderGauge(score, riskLevel, scamType, whyText) {
    const gaugeEl = document.getElementById("risk-gauge-score");
    const labelEl = document.getElementById("risk-verdict-label");
    const descEl = document.getElementById("risk-verdict-desc");
    const circleEl = document.getElementById("gauge-progress-circle");
    const scamTypeBadge = document.getElementById("scam-type-badge");

    if (!gaugeEl) return;

    const clampedScore = Math.max(0, Math.min(100, Math.round(score || 0)));
    gaugeEl.textContent = clampedScore;

    // Circumference for r=58 is 2 * PI * 58 ≈ 364.4
    const circumference = 364.4;
    const offset = circumference - (clampedScore / 100) * circumference;
    if (circleEl) {
      circleEl.style.strokeDashoffset = offset;
    }

    // Determine verdict details and colors based on official hackathon scale
    let level = riskLevel;
    if (!level) {
      if (clampedScore >= 80) level = "CRITICAL RISK";
      else if (clampedScore >= 60) level = "HIGH RISK";
      else if (clampedScore >= 30) level = "CAUTION";
      else level = "LOW RISK";
    }

    if (labelEl) {
      labelEl.textContent = level;
    }

    if (scamTypeBadge && scamType) {
      scamTypeBadge.textContent = scamType;
      scamTypeBadge.style.display = "inline-flex";
    }

    if (level === "CRITICAL RISK") {
      if (labelEl) labelEl.className = "risk-verdict-badge verdict-high";
      if (circleEl) circleEl.style.stroke = "var(--status-danger)";
      if (descEl) descEl.textContent = whyText || "Severe probability of financial exploitation, credential theft, or social engineering manipulation. Do NOT proceed.";
    } else if (level === "HIGH RISK") {
      if (labelEl) labelEl.className = "risk-verdict-badge verdict-high";
      if (circleEl) circleEl.style.stroke = "#f97316";
      if (descEl) descEl.textContent = whyText || "Substantial risk signals detected across communication or destination metadata. Payment is strongly discouraged.";
    } else if (level === "CAUTION") {
      if (labelEl) labelEl.className = "risk-verdict-badge verdict-medium";
      if (circleEl) circleEl.style.stroke = "var(--status-warning)";
      if (descEl) descEl.textContent = whyText || "Unusual patterns or urgency cues detected. Exercise caution and verify credentials.";
    } else {
      if (labelEl) labelEl.className = "risk-verdict-badge verdict-low";
      if (circleEl) circleEl.style.stroke = "var(--status-safe)";
      if (descEl) descEl.textContent = whyText || "Standard benign pattern observed. No manipulation or coercive signals detected.";
    }
  }
};

if (typeof window !== "undefined") {
  window.RiskVisualizer = RiskVisualizer;
}
