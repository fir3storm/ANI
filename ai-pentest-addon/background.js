// Background script - relays messages between sidebar and content scripts
console.log("[BACKGROUND] Background script loaded");

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("[BACKGROUND] Received message:", message);
  
  // Message from sidebar to be forwarded to content script
  if (message.type === "FORWARD_TO_TAB") {
    console.log("[BACKGROUND] Forwarding to tab:", message.category_type);
    browser.tabs.query({active: true, currentWindow: true}).then(tabs => {
      console.log("[BACKGROUND] Active tab:", tabs[0]?.id);
      if (tabs[0]) {
        browser.tabs.sendMessage(tabs[0].id, {
          type: message.category_type,
          category: message.category,
          payloads: message.payloads
        }).then(response => {
          console.log("[BACKGROUND] Message sent to content script");
          if (browser.runtime.lastError) {
            console.error("[BACKGROUND] Send error:", browser.runtime.lastError);
            browser.runtime.sendMessage({
              type: "SCAN_ERROR",
              data: "Could not reach content script. Error: " + browser.runtime.lastError.message
            });
          }
        }).catch(err => {
          console.error("[BACKGROUND] Send failed:", err);
          browser.runtime.sendMessage({
            type: "SCAN_ERROR",
            data: "Failed to send message to tab: " + err.message
          });
        });
      } else {
        console.error("[BACKGROUND] No active tab found");
        browser.runtime.sendMessage({
          type: "SCAN_ERROR",
          data: "No active tab found"
        });
      }
    }).catch(err => {
      console.error("[BACKGROUND] Tab query failed:", err);
      browser.runtime.sendMessage({
        type: "SCAN_ERROR",
        data: "Failed to get active tab: " + err.message
      });
    });
  }
  
  // Message from content script to be forwarded to sidebar
  if (message.type === "SCAN_RESULT" || message.type === "SCAN_COMPLETE" || message.type === "SCAN_ERROR" || message.type === "SCAN_STATUS" || message.type === "DIAGNOSTIC_RESULT") {
    console.log("[BACKGROUND] Forwarding to sidebar:", message.type);
    browser.runtime.sendMessage(message);
  }
});
