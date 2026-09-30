/**
 * SCAMSHIELD AI - Multimodal Analyzers Controller
 * Manages tab filtering and loads test presets without hardcoded scores.
 */

const AnalyzerController = {
  currentTab: "all",

  init() {
    this.bindTabs();
    this.bindPresets();
  },

  bindTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        tabBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        this.currentTab = btn.getAttribute("data-tab");
        this.filterInputs(this.currentTab);
      });
    });
  },

  bindPresets() {
    const selector = document.getElementById("demo-scenario-select");
    if (!selector) return;

    selector.addEventListener("change", (e) => {
      const presetId = e.target.value;
      if (!presetId) return;
      const found = (window.DEMO_PRESETS || []).find(p => p.id === presetId);
      if (found) {
        this.loadPreset(found);
      }
    });
  },

  loadPreset(preset) {
    const msgInput = document.getElementById("input-message");
    const urlInput = document.getElementById("input-url");
    const upiInput = document.getElementById("input-upi");
    const amountInput = document.getElementById("input-amount");
    const reasonInput = document.getElementById("input-reason");

    if (msgInput) msgInput.value = preset.message || "";
    if (urlInput) urlInput.value = preset.url || "";
    if (upiInput) upiInput.value = preset.upiId || "";
    if (amountInput) amountInput.value = preset.amount || "";
    if (reasonInput) reasonInput.value = preset.reason || "";

    // Clear any previous error/feedback message
    const feedbackEl = document.getElementById("scan-feedback-msg");
    if (feedbackEl) feedbackEl.style.display = "none";

    // Trigger dynamic backend analysis for the loaded preset
    if (typeof window.executeScan === "function") {
      window.executeScan();
    }
  },

  filterInputs(tab) {
    const msgGroup = document.getElementById("group-message");
    const urlGroup = document.getElementById("group-url");
    const paymentGroup = document.getElementById("group-payment");
    const reasonGroup = document.getElementById("group-reason");

    if (tab === "message") {
      if (msgGroup) msgGroup.style.display = "flex";
      if (urlGroup) urlGroup.style.display = "none";
      if (paymentGroup) paymentGroup.style.display = "none";
      if (reasonGroup) reasonGroup.style.display = "none";
    } else if (tab === "url") {
      if (msgGroup) msgGroup.style.display = "none";
      if (urlGroup) urlGroup.style.display = "flex";
      if (paymentGroup) paymentGroup.style.display = "none";
      if (reasonGroup) reasonGroup.style.display = "none";
    } else if (tab === "payment") {
      if (msgGroup) msgGroup.style.display = "none";
      if (urlGroup) urlGroup.style.display = "none";
      if (paymentGroup) paymentGroup.style.display = "flex";
      if (reasonGroup) reasonGroup.style.display = "flex";
    } else {
      // all
      if (msgGroup) msgGroup.style.display = "flex";
      if (urlGroup) urlGroup.style.display = "flex";
      if (paymentGroup) paymentGroup.style.display = "flex";
      if (reasonGroup) reasonGroup.style.display = "flex";
    }
  }
};

if (typeof window !== "undefined") {
  window.AnalyzerController = AnalyzerController;
}
