const apiBaseInput = document.getElementById("apiBase");
const textInput = document.getElementById("textInput");
const scanButton = document.getElementById("scanButton");
const grabPageTextButton = document.getElementById("grabPageText");
const resultBox = document.getElementById("result");

function setResult(message, cssClass = "empty") {
  resultBox.className = `result ${cssClass}`;
  resultBox.textContent = message;
}

async function loadSettings() {
  const data = await chrome.storage.local.get(["apiBase"]);
  if (data.apiBase) {
    apiBaseInput.value = data.apiBase;
  }
}

async function saveSettings() {
  await chrome.storage.local.set({ apiBase: apiBaseInput.value.trim() });
}

async function fetchActiveFieldText() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) {
    throw new Error("No active tab found.");
  }
  const response = await chrome.tabs.sendMessage(tab.id, {
    type: "GET_ACTIVE_TEXT"
  });
  return (response && response.text) || "";
}

async function scanText() {
  const text = textInput.value.trim();
  const apiBase = apiBaseInput.value.trim().replace(/\/+$/, "");
  if (!text) {
    setResult("Please enter text to scan.");
    return;
  }
  if (!apiBase) {
    setResult("Please set API base URL.");
    return;
  }

  await saveSettings();
  setResult("Scanning...", "empty");

  try {
    const response = await fetch(`${apiBase}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text,
        policy_profile: "balanced",
        workspace_id: "default"
      })
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || JSON.stringify(data));
    }

    const action = (data.action || "UNKNOWN").toUpperCase();
    const severity = (data.severity || "NONE").toUpperCase();
    const reason = data.reason || "";
    const cssClass = action.toLowerCase();
    setResult(`Action: ${action}\nSeverity: ${severity}\n\n${reason}`, cssClass);
  } catch (error) {
    setResult(`Scan failed: ${error.message || String(error)}`);
  }
}

grabPageTextButton.addEventListener("click", async () => {
  try {
    const activeText = await fetchActiveFieldText();
    if (!activeText) {
      setResult("No active text field content found on this page.");
      return;
    }
    textInput.value = activeText;
    setResult("Loaded text from active page field.");
  } catch (error) {
    setResult(`Could not read active field: ${error.message || String(error)}`);
  }
});

scanButton.addEventListener("click", scanText);
apiBaseInput.addEventListener("change", saveSettings);

loadSettings();
