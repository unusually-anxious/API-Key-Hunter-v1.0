# API Key Hunter v1.0

**API Key Hunter** is a multi-target scanner that discovers exposed API keys across Git repositories, websites, and local directories. It is multi-threaded, async-enabled for high performance, and supports masked-by-default keys with optional full key visibility.

---

## **Features**

- Scan **Git repositories**, including multi-branch and commit history
- Scan **websites** asynchronously with:
  - BFS crawl up to configurable depth
  - Same-domain links only
  - CSP header analysis
  - Sitemap.xml parsing
  - Subdomain detection
- Scan **local directories** for sensitive keys
- Supports detection of over 25 API key patterns (AWS, Google, Stripe, OpenAI, GitHub, Slack, Twilio, and more)
- **Masked-by-default key values**, with `--show-full-keys` toggle
- Multi-format output: TXT, JSON, CSV
- Deduplication of findings
- Logging + progress bars (console + `hunter.log`)
- Termux notifications when findings are detected
- Docker-ready for cross-platform portability

---

## **Installation**

### **Python (Termux/Linux/macOS)**
1. Clone the repo:
```bash
git clone https://github.com/YourUsername/api_key_hunter.git
cd api_key_hunter

Install dependencies

pip install --upgrade pip
pip install -r requirements.txt

Make the script executable:
chmod +x api_key_hunter.py

Docker (Optional, Recommended)
Build Docker image

docker build -t api_key_hunter:1.0 .

Run a scan:
docker run -it --rm api_key_hunter:1.0 --git-repos https://github.com/example/repo.git

Mount local directories if needed:
docker run -it --rm -v ~/projects:/projects api_key_hunter:1.0 --local-dirs /projects


Scan a Git repository:

python api_key_hunter.py --git-repos https://github.com/example/repo.git

Scan websites asynchronously (depth 3):
python api_key_hunter.py --websites https://example.com --depth 3

Scan local directories:

python api_key_hunter.py --local-dirs ~/projects

Scan all targets with full key visibility and multiple output formats:
python api_key_hunter.py \
  --git-repos https://github.com/example/repo.git \
  --websites https://example.com \
  --local-dirs ~/projects \
  --formats txt,json,csv \
  --show-full-keys

Outputs
TXT: findings.txt
JSON: findings.json
CSV: findings.csv
All output files include a summary at the end:


Safety & Disclaimer
Keys are masked by default to protect sensitive information
Use --show-full-keys only when safe to do so
Deduplication ensures no duplicate findings across sources
Only scan repositories, websites, or directories you have permission to analyze
This tool is intended for educational and security auditing purposes only
Contribution & Development
Pull requests welcome!
Suggested structure for contributions:
Add new API key regex patterns in API_PATTERNS
Improve async crawling and subdomain detection
Add tests in tests/ folder
License
This project is licensed under the MIT License.
