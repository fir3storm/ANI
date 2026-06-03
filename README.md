# AI Siege

**Autonomous AI Prompt Injection Pentest Tool**

AI Siege is a powerful penetration testing tool that launches adaptive, AI-powered attacks against chatbot interfaces. It uses **DeepSeek** as the attacker brain to read target AI responses, adapt its strategy, and iteratively craft smarter attacks until it either breaks through or exhausts its attempts.

---

## Features

- **Adaptive Attack Engine** - DeepSeek reads every response and iteratively crafts smarter attacks
- **Firefox Sidebar Addon** - Attacks run directly inside your logged-in browser session
- **20+ Attack Scenarios** - Prompt injection, jailbreak, system prompt extraction, data exfiltration
- **Model Detection** - Identifies if the target is GPT, Claude, Gemini, or other LLMs
- **Strict False-Positive Prevention** - Double-verifies all vulnerabilities before flagging
- **Rich Visual Reports** - Red/green final verdicts with detailed evidence

## How It Works

```
Your Browser (Logged In)    DeepSeek API (Attacker Brain)
         │                            │
    1. Navigate to target AI chat     │
    2. Click attack button ──────────►│
    3. DeepSeek crafts payload ◄──────│
    4. Injects into chat box          │
    5. Captures AI response ─────────►│
    6. DeepSeek analyzes success ◄────│
    7. If failed → craft NEW attack ──│ (repeat)
    8. Final verdict: VULNERABLE/SECURE
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/abhirupguha/ai-siege.git
cd ai-siege
```

### 2. Install the Firefox Addon

1. Open Firefox and go to `about:debugging#/runtime/this-firefox`
2. Click **"Load Temporary Add-on..."**
3. Navigate to `ai-pentest-addon/` and select `manifest.json`
4. The sidebar is now loaded

### 3. Get a DeepSeek API Key

1. Go to [platform.deepseek.com](https://platform.deepseek.com)
2. Create an account and generate an API key
3. Enter this key in the sidebar

### Optional: Python CLI

```bash
pip install -r requirements.txt
playwright install chromium
python -m src.cli scan "https://your-target.com"
```

## Usage

### Adaptive Mode (Recommended)

1. Open Firefox sidebar → AI Siege
2. Enter your DeepSeek API key
3. Select **"Adaptive"** mode
4. Set max rounds (default 15, up to 50)
5. Click any adaptive attack button
6. Watch real-time attack progression
7. **STOP** anytime, or let it run to verdict

### Standard Mode

Uses pre-built payloads for quick testing. Less effective against well-defended targets but useful for baseline testing.

## Attack Categories

| Category | Goal | Rounds |
|----------|------|--------|
| **Prompt Injection** | Override system instructions | Adaptive |
| **Jailbreak** | Break safety restrictions | Adaptive |
| **System Prompt Leak** | Extract hidden instructions | Adaptive |
| **Data Exfiltration** | Generate exfil URLs/markdown | Adaptive |

## Final Verdict

After each scan, AI Siege displays a clear verdict:

- **VULNERABLE (Red)** - AI defenses breached. Shows evidence and attack path.
- **SECURE (Green)** - AI resisted all attacks. Defense is robust.

## Architecture

```
ai-siege/
├── ai-pentest-addon/          # Firefox sidebar addon
│   ├── sidebar.html
│   ├── sidebar.js             # Adaptive attack engine
│   ├── deepseek.js            # DeepSeek API client
│   └── manifest.json
├── src/                       # Python CLI tool
│   ├── browser/               # Playwright automation
│   ├── attacks/               # Attack modules
│   ├── detection/             # Vulnerability analysis
│   ├── reporting/             # HTML/console reports
│   └── cli.py                 # CLI entry point
├── payloads/                  # Attack payloads (JSON)
├── start.bat                  # Windows launcher
└── setup.py
```

## Why "Siege"?

A siege is a sustained, adaptive military operation that probes defenses, learns from each failed assault, and adjusts tactics until the walls are breached. That's exactly what this tool does - it lays siege to AI defenses with adaptive intelligence.

---

## Author

**Abhirup Guha**

---

## Disclaimer

This tool is provided for **authorized security testing only**. Users must obtain explicit written permission before testing any AI system. The author is not responsible for misuse.
