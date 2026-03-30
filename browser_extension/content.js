chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "GET_ACTIVE_TEXT") {
    return;
  }

  const active = document.activeElement;
  if (!active) {
    sendResponse({ text: "" });
    return;
  }

  if (active instanceof HTMLTextAreaElement || active instanceof HTMLInputElement) {
    sendResponse({ text: active.value || "" });
    return;
  }

  if (active.isContentEditable) {
    sendResponse({ text: active.innerText || "" });
    return;
  }

  sendResponse({ text: "" });
});
