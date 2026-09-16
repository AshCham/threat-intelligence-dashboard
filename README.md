# Threat Intelligence Dashboard

A Flask web app I built over the summer to get proper hands-on experience with the VirusTotal API and understand how threat intelligence platforms actually work under the hood. The motivation came from spending too much time manually copy-pasting suspicious IPs and URLs from my home lab's router logs into VirusTotal's web UI one at a time I wanted to automate that.

It queries 70+ antivirus and threat intelligence engines via the VirusTotal v3 API and aggregates the results into a risk verdict. There's also an IOC scan mode where you paste a raw log excerpt and it automatically extracts and analyses every URL and IP it finds.

---

## How it works

**For URL analysis:** VirusTotal doesn't process URLs synchronously. You POST to `/api/v3/urls` and get back an analysis ID, then have to poll `/api/v3/analyses/{id}` until the status flips from `queued` → `in-progress` → `completed`. I built the polling loop from scratch to understand this it wasn't obvious from the docs initially and I burned a few hours thinking something was broken when the results were just still queued.

**For IP analysis:** Much simpler — a single GET to `/api/v3/ip_addresses/{ip}` returns historical detection data, geolocation, and ASN attribution all in one response.

**For IOC scanning:** Regex extraction of `http://` / `https://` URLs and IPv4 addresses from pasted text, deduplication, then sequential analysis of each indicator.

---

## Setup

**1. Clone and enter the directory**
```bash
git clone https://github.com/your-username/threat-intelligence-dashboard.git
cd threat-intelligence-dashboard
```

**2. Set up a virtual environment**
```bash
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # macOS/Linux
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Add your VirusTotal API key**

Get a free key at [virustotal.com](https://www.virustotal.com). Open `.env` and replace the placeholder:
```
VIRUSTOTAL_API_KEY=your_actual_key_here
```

**5. Run it**
```bash
python app.py
```

Then open `http://127.0.0.1:5000`.

---

## The Rate Limit Problem

The free API tier allows **4 requests per minute** and **500 per day**. This hit me immediately while testing the IOC bulk scan feature — submitting 10 URLs in a loop triggered HTTP 429 responses within seconds.

The current handling: a 2-second sleep between requests during bulk scans, and explicit 429 detection in `vt_client.py` that raises a `VTRateLimited` exception rather than crashing silently. The frontend receives a clean error message instead of a 500.

It's not elegant. The proper fix is an async task queue (Celery + Redis) where each VT request runs as a background job, so the Flask thread isn't blocked and you can apply proper backoff between tasks. That's on the TODO list — felt like too much infrastructure to set up for a solo project on a free API tier.

---

## Project Structure

```
threat-intelligence-dashboard/
├── app.py          # Flask routes, risk scoring logic, PDF generation
├── vt_client.py    # VirusTotal API wrapper + custom exceptions
├── templates/
│   └── index.html  # Frontend dashboard (vanilla JS, no frameworks)
├── .env            # API key — do not commit
├── requirements.txt
└── README.md
```

`vt_client.py` handles all the raw HTTP communication with VirusTotal. `app.py` imports from it and deals with request parsing, risk calculation, and response formatting. Kept it to two files — didn't want to over-engineer the structure for what is essentially a single-API wrapper app.

---

## Data Flow

```
Browser
  │
  │  POST /analyse  {target, type}
  ▼
app.py  (Flask routes)
  │
  │  calls vt.scan_url() or vt.check_ip()
  ▼
vt_client.py  (VirusTotalClient)
  │
  │  HTTPS via requests.Session (connection pooling)
  ▼
VirusTotal API v3
  │
  │  JSON response
  ▼
app.py  (_score_risk → risk level + vendor stats)
  │
  │  JSON  {risk_level, malicious, suspicious, ...}
  ▼
Browser  (renders result table + execution log)
```

---

## Known Limitations & Next Steps

**Synchronous URL polling:** The `/analyse` endpoint polls VirusTotal in a blocking loop inside the Flask worker thread. In a multi-user setup, two simultaneous URL submissions will queue behind each other. This isn't a problem for single-user local use but would be unacceptable in production. The fix is moving the polling to a Celery worker — the route would return immediately with a job ID and the frontend would poll a `/status/{job_id}` endpoint.

**No caching:** The same IP queried twice hits the API twice. A Redis TTL cache on `vt_client.check_ip()` keyed on the IP address would fix this — IP reputation data doesn't change minute-to-minute so a 30-minute cache window would be safe and would dramatically reduce quota consumption during bulk log analysis.

**URL edge cases:** Non-standard schemas (`ftp://`, custom port URLs) probably behave unexpectedly and haven't been tested thoroughly. The regex only matches `http://` and `https://`.

**Free tier rate limits on bulk scans:** Anything more than about 5–6 indicators in a bulk IOC scan will start hitting 429 errors. A paid API key (or the public API's less aggressive limits on certain endpoint types) would help, but the real fix is proper async queuing.

**No input sanitisation beyond regex matching:** The app trusts that the VirusTotal API will handle malformed URLs gracefully, which it mostly does. Haven't tested edge cases like URLs with unusual Unicode characters or extremely long paths.

---

## Tech Stack

| Component | What I used |
|---|---|
| Backend | Python 3.10+, Flask |
| VT API integration | requests (with Session + Retry adapter) |
| PDF generation | fpdf2 |
| Config | python-dotenv |
| Frontend | Vanilla HTML/CSS/JS — no frameworks |

---

## Why I didn't use a frontend framework

Honestly, it felt like overkill for a single-page tool. Vanilla JS with `fetch()` is fine for this use case and keeps the deployment dead simple — no build step, no `node_modules`, just Flask serving a static HTML file.
