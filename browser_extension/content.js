const DEFAULT_API_BASE = "http://localhost:8000";
const SCAN_DEBOUNCE_MS = 450;
const MIN_SCAN_CHARS = 8;
const BLOCK_ACTIONS = new Set(["BLOCK"]);
const WARN_ACTIONS = new Set(["FLAG", "REDACT"]);

let apiBase = DEFAULT_API_BASE;
const stateByElement = new WeakMap();
const pendingTimers = new WeakMap();
const bypassSubmitOnce = new WeakSet();

function isEditableElement(element) {
  if (!(element instanceof HTMLElement)) {
    return false;
  }
  if (element instanceof HTMLTextAreaElement) {
    return !element.readOnly && !element.disabled;
  }
  if (element instanceof HTMLInputElement) {
    const allowedTypes = new Set([
      "text",
      "search",
      "url",
      "email",
      "tel",
      "password",
      ""
    ]);
    return allowedTypes.has((element.type || "").toLowerCase()) && !element.readOnly && !element.disabled;
  }
  return element.isContentEditable;
}

function getEditableText(element) {
  if (!isEditableElement(element)) {
    return "";
  }
  if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
    return (element.value || "").trim();
  }
  return (element.innerText || "").trim();
}

function ensureStyles() {
  if (document.getElementById("sf-live-guard-styles")) {
    return;
  }
  const style = document.createElement("style");
  style.id = "sf-live-guard-styles";
  style.textContent = `
    .sf-live-banner {
      position: fixed;
      top: 12px;
      right: 12px;
      z-index: 2147483647;
      max-width: 360px;
      border-radius: 8px;
      padding: 10px 12px;
      font: 600 12px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      box-shadow: 0 10px 24px rgba(0,0,0,0.2);
      border: 1px solid transparent;
      backdrop-filter: blur(4px);
      opacity: 0;
      transform: translateY(-6px);
      transition: opacity 140ms ease, transform 140ms ease;
      pointer-events: none;
    }
    .sf-live-banner.show {
      opacity: 1;
      transform: translateY(0);
    }
    .sf-live-banner.warn {
      background: rgba(120, 53, 15, 0.92);
      color: #ffedd5;
      border-color: rgba(251, 146, 60, 0.8);
    }
    .sf-live-banner.block {
      background: rgba(127, 29, 29, 0.94);
      color: #fee2e2;
      border-color: rgba(248, 113, 113, 0.8);
    }
    .sf-live-banner.info {
      background: rgba(30, 58, 138, 0.92);
      color: #dbeafe;
      border-color: rgba(96, 165, 250, 0.75);
    }
  `;
  document.documentElement.appendChild(style);
}

function getOrCreateBanner() {
  ensureStyles();
  let banner = document.getElementById("sf-live-banner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "sf-live-banner";
    banner.className = "sf-live-banner info";
    document.documentElement.appendChild(banner);
  }
  return banner;
}

let bannerHideTimer = null;
function showBanner(message, kind = "info", durationMs = 2600) {
  const banner = getOrCreateBanner();
  banner.className = `sf-live-banner ${kind}`;
  banner.textContent = message;
  requestAnimationFrame(() => banner.classList.add("show"));
  if (bannerHideTimer) {
    clearTimeout(bannerHideTimer);
  }
  bannerHideTimer = setTimeout(() => {
    banner.classList.remove("show");
  }, durationMs);
}

function applyFieldVisual(element, mode) {
  if (!isEditableElement(element)) {
    return;
  }
  if (!element.dataset.sfPrevOutline) {
    element.dataset.sfPrevOutline = element.style.outline || "";
  }
  if (mode === "block") {
    element.style.outline = "2px solid #ef4444";
    element.style.outlineOffset = "1px";
  } else if (mode === "warn") {
    element.style.outline = "2px solid #f59e0b";
    element.style.outlineOffset = "1px";
  } else {
    element.style.outline = element.dataset.sfPrevOutline || "";
    element.style.outlineOffset = "";
  }
}

async function analyzeText(text) {
  const base = (apiBase || DEFAULT_API_BASE).replace(/\/+$/, "");
  const response = await fetch(`${base}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text,
      policy_profile: "balanced",
      workspace_id: "default"
    })
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload && payload.detail ? payload.detail : `HTTP ${response.status}`;
    throw new Error(detail);
  }
  const action = String(payload.action || "ALLOW").toUpperCase();
  const severity = String(payload.severity || "NONE").toUpperCase();
  return {
    action,
    severity,
    reason: payload.reason || ""
  };
}

async function scanAndUpdate(element, text) {
  const state = stateByElement.get(element) || {};
  state.scanning = true;
  state.currentText = text;
  stateByElement.set(element, state);

  try {
    const result = await analyzeText(text);
    const blocked = BLOCK_ACTIONS.has(result.action);
    const warned = WARN_ACTIONS.has(result.action);
    state.lastResult = {
      text,
      blocked,
      warned,
      action: result.action,
      severity: result.severity,
      reason: result.reason
    };
    state.scanning = false;
    stateByElement.set(element, state);

    if (blocked) {
      applyFieldVisual(element, "block");
      showBanner(`Blocked prompt (${result.action}/${result.severity}): ${result.reason || "Potential malicious content."}`, "block");
    } else if (warned) {
      applyFieldVisual(element, "warn");
    } else {
      applyFieldVisual(element, "clear");
    }
    return state.lastResult;
  } catch (_error) {
    state.scanning = false;
    state.lastResult = null;
    stateByElement.set(element, state);
    applyFieldVisual(element, "clear");
    return null;
  }
}

function scheduleLiveScan(element) {
  if (!isEditableElement(element)) {
    return;
  }
  const text = getEditableText(element);
  if (text.length < MIN_SCAN_CHARS) {
    const state = stateByElement.get(element);
    if (state) {
      state.lastResult = null;
      state.currentText = text;
      stateByElement.set(element, state);
    }
    applyFieldVisual(element, "clear");
    return;
  }

  const existing = pendingTimers.get(element);
  if (existing) {
    clearTimeout(existing);
  }
  const timer = setTimeout(() => {
    scanAndUpdate(element, text);
  }, SCAN_DEBOUNCE_MS);
  pendingTimers.set(element, timer);
}

function getPrimaryEditableFromForm(form) {
  const candidates = form.querySelectorAll("textarea, input[type='text'], input[type='search'], input[type='email'], input[type='url'], input[type='tel'], input[type='password'], [contenteditable='true']");
  let best = null;
  let bestLen = 0;
  for (const candidate of candidates) {
    const text = getEditableText(candidate);
    if (text.length > bestLen) {
      best = candidate;
      bestLen = text.length;
    }
  }
  return best;
}

async function shouldBlockElement(element) {
  const text = getEditableText(element);
  if (!text || text.length < MIN_SCAN_CHARS) {
    return false;
  }
  const state = stateByElement.get(element);
  if (state && state.lastResult && state.lastResult.text === text) {
    return state.lastResult.blocked;
  }
  const result = await scanAndUpdate(element, text);
  return !!(result && result.blocked);
}

async function handleSubmit(event) {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }
  if (bypassSubmitOnce.has(form)) {
    bypassSubmitOnce.delete(form);
    return;
  }

  const active = document.activeElement;
  const editable = isEditableElement(active) ? active : getPrimaryEditableFromForm(form);
  if (!editable) {
    return;
  }
  const text = getEditableText(editable);
  if (!text || text.length < MIN_SCAN_CHARS) {
    return;
  }

  // Pause submit immediately, then allow it only if scan clears.
  event.preventDefault();
  event.stopPropagation();

  const blocked = await shouldBlockElement(editable);
  if (blocked) {
    showBanner("Semantic Firewall blocked this prompt before submit.", "block", 3200);
    return;
  }

  bypassSubmitOnce.add(form);
  form.requestSubmit();
}

function handleKeydown(event) {
  if (event.key !== "Enter" || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey) {
    return;
  }
  const target = event.target;
  if (!isEditableElement(target)) {
    return;
  }
  const text = getEditableText(target);
  const state = stateByElement.get(target);
  const blocked = !!(
    state &&
    state.lastResult &&
    state.lastResult.text === text &&
    state.lastResult.blocked
  );
  if (blocked) {
    event.preventDefault();
    event.stopPropagation();
    showBanner("Semantic Firewall blocked this prompt.", "block", 2800);
  }
}

async function loadSettings() {
  try {
    const data = await chrome.storage.local.get(["apiBase"]);
    apiBase = data.apiBase ? String(data.apiBase).trim() : DEFAULT_API_BASE;
  } catch (_error) {
    apiBase = DEFAULT_API_BASE;
  }
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.apiBase) {
    return;
  }
  apiBase = String(changes.apiBase.newValue || DEFAULT_API_BASE).trim();
});

document.addEventListener(
  "input",
  (event) => {
    if (isEditableElement(event.target)) {
      scheduleLiveScan(event.target);
    }
  },
  true
);

document.addEventListener(
  "focusin",
  (event) => {
    if (isEditableElement(event.target)) {
      scheduleLiveScan(event.target);
    }
  },
  true
);

window.addEventListener("submit", (event) => {
  handleSubmit(event);
}, true);

// --- PLATFORM SPECIFIC INTERCEPTORS ---
const PLATFORM_SELECTORS = [
  'button[data-testid="send-button"]', // ChatGPT
  'button[aria-label="Send message"]', // Claude
  'button.send-button', // General fallback
];

async function handlePlatformClick(event) {
  // Check if click was on or inside a known "Send" button
  let targetBtn = null;
  for (const selector of PLATFORM_SELECTORS) {
    targetBtn = event.target.closest(selector);
    if (targetBtn) break;
  }

  if (!targetBtn) return;

  // Find the nearest editable field (the chat box)
  const editable = getPrimaryEditableFromForm(document.body);
  if (!editable) return;

  const text = getEditableText(editable);
  if (!text || text.length < MIN_SCAN_CHARS) return;

  // If we haven't scanned it yet, pause the click!
  event.preventDefault();
  event.stopPropagation();
  event.stopImmediatePropagation();

  const blocked = await shouldBlockElement(editable);
  if (blocked) {
    showBanner("Semantic Firewall blocked this prompt before sending to the AI.", "block", 3200);
    return;
  }

  // If safe, temporarily remove our interceptor and click the button programmatically
  document.removeEventListener("click", handlePlatformClick, true);
  targetBtn.click();
  // Re-attach interceptor after click goes through
  setTimeout(() => {
    document.addEventListener("click", handlePlatformClick, true);
  }, 100);
}

document.addEventListener("click", handlePlatformClick, true);

document.addEventListener("keydown", (event) => {
  handleKeydown(event);
}, true);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "GET_ACTIVE_TEXT") {
    return;
  }

  const active = document.activeElement;
  if (!active) {
    sendResponse({ text: "" });
    return;
  }
  sendResponse({ text: getEditableText(active) || "" });
});

loadSettings();
