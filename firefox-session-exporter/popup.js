document.getElementById('exportBtn').addEventListener('click', async () => {
  try {
    const [tab] = await browser.tabs.query({active: true, currentWindow: true});
    const url = new URL(tab.url);
    
    // Get all cookies for the current URL
    const cookies = await browser.cookies.getAll({url: tab.url});
    
    // Format for Playwright storage_state
    const playwrightSession = {
      cookies: cookies.map(c => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        expires: c.expirationDate || -1,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite === 'no_restriction' ? 'None' : (c.sameSite === 'lax' ? 'Lax' : 'Strict')
      })),
      origins: []
    };
    
    // Create and trigger download using standard HTML5 download attribute
    const jsonString = JSON.stringify(playwrightSession, null, 2);
    const blob = new Blob([jsonString], {type: 'application/json'});
    const downloadUrl = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = `session_${url.hostname.replace(/\./g, '_')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(downloadUrl);
    
    document.getElementById('status').innerText = "Session exported successfully!";
    document.getElementById('status').style.color = "#4ade80";
    document.getElementById('status').style.display = 'block';
    
    setTimeout(() => { window.close(); }, 1500);
  } catch (error) {
    console.error("Export failed:", error);
    document.getElementById('status').innerText = "Export failed: " + error.message;
    document.getElementById('status').style.color = "#f87171";
    document.getElementById('status').style.display = 'block';
  }
});
