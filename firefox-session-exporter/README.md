# firefox-session-exporter

A small Firefox companion extension for ANI. It exports the cookies of the active tab into a JSON file in the format the ANI CLI's `--session-file` option expects.

ANI's main sidebar add-on (`ani-addon/`) drives the attack loop, but it does not have an easy way to *export* a session cookie for use with the headless CLI on another machine. This extension fills that gap.

## Install

1. Open Firefox and go to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Open `firefox-session-exporter/manifest.json`.
4. The extension's icon appears in the toolbar.

## Use

1. Log in to the target chat application in Firefox as you normally would.
2. Click the extension icon. A small popup lists the cookies for the active tab's domain.
3. Click **Export**. A JSON file is downloaded. The file is named `<domain>-<timestamp>.json` and has the shape:

   ```json
   {
     "cookies": [
       {
         "name": "session",
         "value": "...",
         "domain": ".example.com",
         "path": "/",
         "expires": 1735689600,
         "httpOnly": true,
         "secure": true,
         "sameSite": "Lax"
       }
     ],
     "origins": [
       {
         "origin": "https://example.com",
         "localStorage": { "k": "v" }
       }
     ]
   }
   ```

   The shape mirrors Playwright's `context.storage_state()` output, which is what ANI's `AuthHandler` already parses when you pass `--session-file`.

4. Move the file to the machine where ANI's CLI runs (or `scp`, or share via your secret manager of choice — do not paste it into chat).
5. Run the scan with the file:

   ```bash
   python -m src.cli scan "https://your-target.example" \
       --auth session \
       --session-file /path/to/example.com-20260616.json
   ```

## What it does not do

- It does not store cookies anywhere. The export is a one-shot download from the browser.
- It does not call ANI's API or any other network endpoint.
- It does not modify the cookies; it reads them and writes them to the file you download.

## Security notes

- Exported session files contain bearer-equivalent credentials. Treat them like passwords: store encrypted (ANI Fernet-encrypts them on the CLI side once it ingests them) and never commit them to git.
- The downloaded JSON is what ANI's `--session-file` consumes directly. The CLI's session-loader transparently handles both plain and Fernet-encrypted files.
- The extension is loaded as a temporary add-on; Firefox revokes its permissions when Firefox restarts. Re-load it if you close and reopen the browser.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | WebExtension manifest (MV2). Permissions: `cookies`, `activeTab`, `storage`, `downloads`. |
| `popup.html` | The toolbar popup UI. |
| `popup.js` | Reads cookies via `browser.cookies.getAll`, builds the JSON, triggers the download. |
