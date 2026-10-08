# PhishGuard — Real-Time Background Phishing & Malicious URL Protection

PhishGuard is a cybersecurity system providing automated, real-time protection against phishing, malware, and defacement URLs across web browsing sessions (including Gmail, WhatsApp Web, social feeds, and web applications).

PhishGuard is powered by a high-performance **Random Forest Classifier** trained on 651,191 URLs, delivering **94.4% accuracy** across 22 structural URL features with calibrated probability scores and explainable threat indicators.

---

## 🚀 Key Features

- **Zero-Terminal Silent Operation:** Runs in the background via a windowless Windows background runner (`pythonw.exe`). No terminal window or manual `python app.py` execution is ever required.
- **Auto-Start With Windows:** Configured to start silently upon Windows login via a single setup command.
- **Deep Webpage Integration:** A Chrome Manifest V3 extension monitors active links and dynamically inserted content (Gmail emails, WhatsApp chats, social media feeds) via a debounced `MutationObserver`.
- **Pre-Emptive Click Interception:** Injects a cyber-themed warning modal before navigation occurs when a suspicious or malicious link is clicked.
- **LRU In-Memory & Storage Deduplication:** Caches verified safe and malicious URLs locally to prevent redundant inference requests and ensure zero page lag.
- **Stand-Alone Security Dashboard:** Complete security console featuring live telemetry, full scan history with search/filter, a manual URL inspector with all 22 feature breakdowns, and an email/message text scanner.
- **100% Privacy by Design:** All URL feature extraction and inference happen locally on your computer (`127.0.0.1:8765`). No personal data, passwords, OTPs, or private chat contents are ever collected or sent to cloud servers.

---

## 📁 Project Architecture

```
phishguard/
│
├── extension/                       # Chrome Manifest V3 Extension
│   ├── manifest.json                # Extension manifest configuration
│   ├── background/
│   │   └── service_worker.js        # Background worker, LRU cache, badge & state
│   ├── content/
│   │   ├── content.js               # Dynamic DOM observer (Gmail/WhatsApp Web) & interceptor
│   │   └── warning_modal.js         # Injected security warning modal component
│   ├── popup/
│   │   ├── popup.html               # Shield extension popup UI
│   │   ├── popup.js                 # Popup controller & quick-scan logic
│   │   └── popup.css                # Dark navy cybersecurity styling
│   ├── warning/
│   │   └── warning.css              # Cyber warning modal & threat indicator styles
│   ├── dashboard/
│   │   ├── dashboard.html           # Full threat intelligence dashboard
│   │   ├── dashboard.js             # Telemetry, history table, manual & message scanners
│   │   └── dashboard.css            # Responsive security console stylesheet
│   ├── assets/                      # Extension icons (16px, 32px, 48px, 128px)
│   └── test_webpage.html            # Webmail & WhatsApp Web simulation test harness
│
├── ml/                              # Real Machine Learning & Multi-Signal Layer
│   ├── feature_extractor.py         # 22 trained URL features & explainability engine
│   ├── model_loader.py              # Memory-mapped joblib loader for 1.04 GB model
│   ├── domain_analyzer.py           # Public Suffix parser, brand registry & deception indicators
│   ├── decision_engine.py           # Multi-signal decision layer (ML + domain + impersonation)
│   └── inference_engine.py          # Unified inference pipeline with transparent ML metrics
│
├── companion/                       # Silent Local Companion Microservice
│   ├── server.py                    # High-throughput FastAPI service on 127.0.0.1:8765
│   ├── run_silent.vbs               # Windowless VBScript runner (no cmd window)
│   ├── start_companion.bat          # Startup utility
│   ├── stop_companion.bat           # Graceful shutdown utility
│   ├── register_autostart.bat       # Registers service in Windows Startup
│   └── unregister_autostart.bat     # Removes service from Windows Startup
│
├── mobile/                          # Mobile Platform Architecture & Prototype
│   └── README.md                    # Android (Intents/Share/Accessibility) & iOS blueprint
│
├── scripts/                         # Utilities & Testing
│   ├── setup_phishguard.bat         # 1-Click Master Installer
│   ├── benchmark_accuracy.py        # 50-URL benchmark suite (Before vs After metrics)
│   ├── create_zip.py                # Release packager
│   ├── test_companion.py            # API health & inference verification script
│   └── test_samples.py              # Sample dataset prediction benchmark
│
└── extracted/                       # User-Provided Trained Model & Dataset
    └── ML REVIEW 2/
        ├── phishguard_model.pkl     # 1.04 GB Trained Random Forest (200 trees, depth 30)
        ├── phishguard_label_encoder (3).pkl
        ├── phishguard_feature_names (2).pkl
        └── malicious_phish.csv      # 651,191 Labeled URL Dataset
```

---

## 🛡️ Multi-Signal Phishing Decision Layer (False Positive Resolution)

### Root Cause Analysis
During comprehensive tree inspection, an inherent dataset bias was identified in `malicious_phish.csv`:
- **99.44%** of benign training URLs were formatted without protocol prefixes (e.g. `mp3raid.com/music/...`), whereas phishing URLs contained `https://`.
- In the trained Random Forest model, Tree splits heavily penalize `has_https == 1` and `slash_count > 2.50`.
- As a result, legitimate modern HTTPS navigation URLs like `https://mail.google.com/`, `https://chatgpt.com/`, and `https://login.microsoftonline.com/` were erroneously classified as phishing with high confidence by the raw ML model alone.

### Multi-Signal Decision Architecture
PhishGuard does not use a simplistic static whitelist that bypasses inspection. Instead, it fuses:
1. **Raw Machine Learning Prediction:** Random Forest class probabilities across 22 structural URL features.
2. **Public Suffix Domain Decomposition:** Accurately separates multi-part TLDs (`.co.uk`, `.com.br`, `.co.za`, `.com.au`) to determine the authentic registrable domain.
3. **Brand Impersonation Detection:** Cross-checks brand tokens against authorized apex domains. Subdomain impersonation (`google.com.evil.example`) or lookalike domains (`chatgpt-login-free.example`, `google-login-security.example`) are flagged as **CRITICAL PHISHING THREATS**.
4. **Hostile Deception Indicators:** Flags `@` credential spoofing, raw IP addresses, punycode/homograph domains, disposable TLDs (`.tk`, `.xyz`), non-standard ports, and high-entropy domain names (DGA).
5. **Full ML Transparency:** The raw ML prediction (`ml_prediction`), ML confidence, and probabilities are preserved and displayed across the Dashboard, Popup, and Warning Modals alongside the Final Protection Decision.

### Benchmark Evaluation (50-URL Standardized Test Suite)

| Evaluation Metric | Before (Raw ML Model Alone) | After (Multi-Signal Decision Layer) |
|---|:---:|:---:|
| **Precision** | **39.13%** | **100.00%** |
| **Recall (Detection Rate)** | **94.74%** | **100.00%** |
| **F1 Score** | **55.38%** | **100.00%** |
| **False Positive Rate (FPR)** | **90.32%** (28/31 blocked) | **0.00%** (0/31 blocked) |
| **False Negative Rate (FNR)** | **5.26%** | **0.00%** |
| **Overall Accuracy** | **42.00%** | **100.00%** |


---

## 📊 ML Model & Feature Engineering

### Trained Model Specifications
- **Architecture:** `sklearn.ensemble.RandomForestClassifier`
- **Trees (`n_estimators`):** 200 trees
- **Max Depth (`max_depth`):** 30
- **Size on Disk:** 1,046 MB (~1.04 GB)
- **Target Threat Classes:**
  1. `benign` (Safe legitimate URLs)
  2. `phishing` (Credential harvesters & spoofed portals)
  3. `malware` (Malicious payload distribution links)
  4. `defacement` (Compromised web infrastructure)

### The 22 Extracted Features
1. `url_length` — Total character length of URL
2. `hostname_length` — Length of hostname/domain
3. `path_length` — Length of URL path
4. `dot_count` — Total `.` characters
5. `hyphen_count` — Total `-` characters
6. `underscore_count` — Total `_` characters
7. `slash_count` — Total `/` characters (13.83% importance)
8. `question_count` — Total `?` characters
9. `equal_count` — Total `=` characters
10. `at_count` — Total `@` characters
11. `and_count` — Total `&` characters
12. `digit_count` — Total numeric digits `[0-9]`
13. `letter_count` — Total alphabetic characters `[a-zA-Z]`
14. `digit_ratio` — Ratio of digits to total characters
15. `has_https` — Binary indicator of HTTPS protocol
16. `has_ip` — Binary indicator of raw IPv4 host
17. `subdomain_count` — Number of subdomain levels
18. `has_suspicious_word` — Binary indicator of 13 sensitive tokens (`login`, `signin`, `verify`, `account`, `update`, `secure`, `bank`, `confirm`, `password`, `free`, `click`, `ebayisapi`, `webscr`)
19. `has_port` — Non-default service port flag
20. `double_slash_redirect` — Occurrence of `//` after position 7
21. `tld_length` — Top-level domain extension length
22. `num_params` — Count of query parameters

---

## ⚡ 1-Click Setup & Installation

### Step 1: Run Master Installer
Double-click `scripts\setup_phishguard.bat` or run in PowerShell:
```cmd
scripts\setup_phishguard.bat
```
This script will:
- Verify your Python environment.
- Register the silent runner in your Windows Startup directory (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`).
- Start the companion microservice silently in the background on port `8765`.
- Validate that the ML model responds to test queries in < 2ms.

### Step 2: Load Extension in Google Chrome
1. Open Google Chrome and enter `chrome://extensions` in the address bar.
2. In the top-right corner, switch on **Developer mode**.
3. Click the **Load unpacked** button.
4. Select the `extension/` folder inside `phishguard`.
5. You will see the **PhishGuard Shield** icon appear in your Chrome toolbar.

---

## 🧪 Testing the Complete Workflow

1. Open `extension\test_webpage.html` in Chrome:
   - Notice the simulation of Gmail and WhatsApp Web messages.
   - PhishGuard automatically analyzes the links in the background.
   - Malicious links are subtly flagged with a red border and `⚠️ THREAT` badge.
2. Click any flagged link (e.g. `http://br-icloud.com.br`):
   - The navigation is pre-emptively intercepted.
   - The **⚠️ POTENTIALLY PHISHING LINK** warning modal appears displaying the URL, confidence score, threat category, and why it was flagged.
   - Click **🛡️ Go Back** to remain safe, or **Continue Anyway** to test override.
3. Click the **Simulate Incoming WhatsApp Phishing Message** button:
   - A new message element is inserted into the DOM.
   - The `MutationObserver` detects it, batches it for scan, and flags the threat without requiring page reload.
4. Click the PhishGuard toolbar icon to open the **Popup UI**:
   - View real-time counters (Scanned, Threats, Safe).
   - Toggle protection ON/OFF.
5. Click **Open Dashboard →**:
   - Inspect the comprehensive telemetry overview, search the full scan history, analyze individual URLs with the 22-feature manual inspector, and test message texts in the message scanner.
