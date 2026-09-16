import re
import io
import os
import logging
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, send_file
from dotenv import load_dotenv
from fpdf import FPDF

from vt_client import VirusTotalClient, VTError, VTBadKey, VTRateLimited, VTNotFound, VTTimeout

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger(__name__)

app = Flask(__name__)

_IP_RE = re.compile(
    r"\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
# catches standard http/https URLs - edge case: ftp:// and custom ports probably
# behave unexpectedly here but haven't had time to test those properly
# TODO: validate/strip URL schema before submission - non-http URLs can crash the VT endpoint
_URL_RE = re.compile(r"https?://[^\s<>\"'`\]\[{}|\\^]+")

RECOMMENDATIONS = {
    "HIGH":    "BLOCK IMMEDIATELY. Multiple security vendors have flagged this target as malicious. Do not interact with it. Escalate to your security team.",
    "MEDIUM":  "PROCEED WITH CAUTION. Some vendors are flagging suspicious activity. Investigate further before allowing access. Consider sandbox detonation.",
    "LOW":     "APPEARS SAFE. No significant threats detected across vendor engines. Continue standard monitoring.",
    "UNKNOWN": "INSUFFICIENT DATA. Could not determine threat level. Manual investigation recommended.",
}


def _make_client():
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key or api_key == "your_key_here":
        raise RuntimeError("VIRUSTOTAL_API_KEY not set in .env")
    return VirusTotalClient(api_key)


def _score_risk(vendor_stats):
    positives_count  = vendor_stats.get("malicious", 0)
    suspicious_count = vendor_stats.get("suspicious", 0)
    if positives_count > 5:
        return "HIGH", "red"
    if positives_count > 0 or suspicious_count > 3:
        return "MEDIUM", "orange"
    return "LOW", "green"


def _vt_error_resp(exc):
    return jsonify({"error": str(exc)}), (exc.http_code or 502)


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    req_data    = request.get_json(silent=True) or {}
    target      = (req_data.get("target") or "").strip()
    target_type = (req_data.get("type") or "").strip().lower()

    if not target:
        return jsonify({"error": "No target provided."}), 400
    if target_type not in ("url", "ip"):
        target_type = "ip" if _IP_RE.match(target) else "url"

    log.info("Analysis request — type=%s target=%s", target_type, target)

    try:
        vt = _make_client()

        if target_type == "ip":
            vt_report   = vt.check_ip(target)
            vt_attrs    = vt_report["data"]["attributes"]
            vendor_stats = vt_attrs.get("last_analysis_stats", {})
            risk, color  = _score_risk(vendor_stats)
            analysis_result = {
                "target":     target,
                "type":       "IP Address",
                "risk_level": risk,
                "risk_color": color,
                "malicious":  vendor_stats.get("malicious", 0),
                "suspicious": vendor_stats.get("suspicious", 0),
                "harmless":   vendor_stats.get("harmless", 0),
                "undetected": vendor_stats.get("undetected", 0),
                "country":    vt_attrs.get("country", "Unknown"),
                "asn":        vt_attrs.get("asn", "N/A"),
                "as_owner":   vt_attrs.get("as_owner", "Unknown"),
                "recommendation": RECOMMENDATIONS[risk],
                "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
        else:
            vt_report    = vt.scan_url(target)
            vt_attrs     = vt_report["data"]["attributes"]
            # VT returns "stats" for fresh scans, "last_analysis_stats" for cached ones
            vendor_stats = vt_attrs.get("stats") or vt_attrs.get("last_analysis_stats", {})
            risk, color  = _score_risk(vendor_stats)
            analysis_result = {
                "target":     target,
                "type":       "URL",
                "risk_level": risk,
                "risk_color": color,
                "malicious":  vendor_stats.get("malicious", 0),
                "suspicious": vendor_stats.get("suspicious", 0),
                "harmless":   vendor_stats.get("harmless", 0),
                "undetected": vendor_stats.get("undetected", 0),
                "recommendation": RECOMMENDATIONS[risk],
                "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            }

        return jsonify(analysis_result)

    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500
    except (VTBadKey, VTRateLimited, VTNotFound, VTTimeout, VTError) as exc:
        return _vt_error_resp(exc)
    except Exception as exc:
        log.exception("Unexpected crash in /analyse")
        return jsonify({"error": f"Something went wrong: {exc}"}), 500


@app.route("/ioc-scan", methods=["POST"])
def ioc_scan():
    req_data = request.get_json(silent=True) or {}
    raw_text = (req_data.get("text") or "").strip()

    if not raw_text:
        return jsonify({"error": "No text provided."}), 400

    # pull out all URLs and IPs from whatever blob of text the user pasted
    extracted_urls = list(dict.fromkeys(_URL_RE.findall(raw_text)))
    extracted_ips  = list(dict.fromkeys(m.group(0) for m in _IP_RE.finditer(raw_text)))

    # filter out IPs that are just part of a URL we already have
    # TODO: add a proper deduplication step here - same IP appearing in two different
    # URLs will still get queried twice, which burns quota unnecessarily
    url_concat    = " ".join(extracted_urls)
    standalone_ips = [ip for ip in extracted_ips if ip not in url_concat]

    indicators = (
        [{"target": u,  "type": "url"} for u in extracted_urls[:10]] +
        [{"target": ip, "type": "ip"}  for ip in standalone_ips[:10]]
    )[:20]

    if not indicators:
        return jsonify({"error": "No URLs or IP addresses found in the provided text."}), 400

    log.info("IOC scan — %d indicators extracted from %d chars", len(indicators), len(raw_text))

    ioc_results = []
    try:
        vt = _make_client()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500

    for i, ind in enumerate(indicators):
        if i > 0:
            import time; time.sleep(2)  # basic rate-limit buffer - free tier is 4 req/min

        try:
            if ind["type"] == "ip":
                vt_report    = vt.check_ip(ind["target"])
                vt_attrs     = vt_report["data"]["attributes"]
                vendor_stats = vt_attrs.get("last_analysis_stats", {})
                risk, color  = _score_risk(vendor_stats)
                ioc_results.append({
                    "target":     ind["target"],
                    "type":       "IP Address",
                    "risk_level": risk,
                    "risk_color": color,
                    "malicious":  vendor_stats.get("malicious", 0),
                    "suspicious": vendor_stats.get("suspicious", 0),
                    "harmless":   vendor_stats.get("harmless", 0),
                    "undetected": vendor_stats.get("undetected", 0),
                    "country":    vt_attrs.get("country", "Unknown"),
                    "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                })
            else:
                vt_report    = vt.scan_url(ind["target"])
                vt_attrs     = vt_report["data"]["attributes"]
                vendor_stats = vt_attrs.get("stats") or vt_attrs.get("last_analysis_stats", {})
                risk, color  = _score_risk(vendor_stats)
                ioc_results.append({
                    "target":     ind["target"],
                    "type":       "URL",
                    "risk_level": risk,
                    "risk_color": color,
                    "malicious":  vendor_stats.get("malicious", 0),
                    "suspicious": vendor_stats.get("suspicious", 0),
                    "harmless":   vendor_stats.get("harmless", 0),
                    "undetected": vendor_stats.get("undetected", 0),
                    "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                })

        except VTRateLimited as exc:
            log.warning("Rate limited on indicator %d/%d", i + 1, len(indicators))
            ioc_results.append({
                "target": ind["target"], "type": ind["type"].upper(),
                "risk_level": "UNKNOWN", "risk_color": "grey",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            })
        except VTError as exc:
            log.warning("VT error on %s: %s", ind["target"], exc)
            ioc_results.append({
                "target": ind["target"], "type": ind["type"].upper(),
                "risk_level": "UNKNOWN", "risk_color": "grey",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            })

    return jsonify({"results": ioc_results, "total": len(ioc_results)})


@app.route("/export-pdf", methods=["POST"])
def export_pdf():
    req_data = request.get_json(silent=True) or {}
    results  = req_data.get("results", [])

    if not results:
        return jsonify({"error": "No results to export."}), 400

    try:
        pdf_bytes = _generate_pdf(results)
        filename  = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as exc:
        log.exception("PDF generation failed")
        return jsonify({"error": f"PDF generation failed: {exc}"}), 500


# ── PDF generation ──────────────────────────────────────────────────────────

def _safe(val) -> str:
    if val is None:
        return ""
    return str(val).encode("latin-1", errors="replace").decode("latin-1")


def _generate_pdf(results: list) -> bytes:
    RISK_RGB = {
        "HIGH":    (220, 38,  38),
        "MEDIUM":  (180, 120, 10),
        "LOW":     (34,  150, 60),
        "UNKNOWN": (100, 100, 100),
    }

    counts = {k: 0 for k in RISK_RGB}
    for r in results:
        lvl = r.get("risk_level", "UNKNOWN")
        counts[lvl] = counts.get(lvl, 0) + 1

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # header
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 44, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_xy(14, 10)
    pdf.cell(0, 10, "Threat Intelligence Report", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_xy(14, 24)
    pdf.cell(0, 5, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True)
    pdf.set_xy(14, 31)
    pdf.cell(0, 5, f"Total indicators: {len(results)}", ln=True)

    # summary boxes
    pdf.set_y(54)
    pdf.set_text_color(40, 40, 40)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_x(14)
    pdf.cell(0, 7, "Risk Summary", ln=True)
    pdf.ln(2)
    y0, box_w = pdf.get_y(), 42
    for i, (label, rgb) in enumerate(RISK_RGB.items()):
        x = 14 + i * (box_w + 3)
        pdf.set_fill_color(*rgb)
        pdf.rect(x, y0, box_w, 24, "F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_xy(x, y0 + 1)
        pdf.cell(box_w, 12, str(counts[label]), align="C", ln=False)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_xy(x, y0 + 14)
        pdf.cell(box_w, 8, label, align="C", ln=False)

    pdf.set_y(y0 + 32)
    pdf.set_draw_color(210, 210, 210)
    pdf.set_line_width(0.3)
    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
    pdf.ln(6)

    pdf.set_text_color(40, 40, 40)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_x(14)
    pdf.cell(0, 7, "Indicator Details", ln=True)
    pdf.ln(2)

    for idx, r in enumerate(results, 1):
        if pdf.get_y() > 235:
            pdf.add_page()

        risk = r.get("risk_level", "UNKNOWN")
        rgb  = RISK_RGB.get(risk, (100, 100, 100))

        pdf.set_fill_color(*rgb)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_x(14)
        pdf.cell(182, 7, f"  {idx}.  {_safe(r.get('type', 'UNKNOWN'))}  -  {risk}", fill=True, ln=True)

        pdf.set_fill_color(247, 249, 252)
        pdf.set_text_color(50, 50, 50)

        def row(label, val):
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_x(14)
            pdf.cell(28, 6, label, fill=True, ln=False)
            pdf.set_font("Courier", "", 7)
            pdf.cell(154, 6, _safe(str(val))[:100], fill=True, ln=True)

        row("Target:", r.get("target", "N/A"))
        if r.get("timestamp"):
            row("Timestamp:", r["timestamp"])
        if r.get("country"):
            country_info = _safe(r["country"])
            if r.get("as_owner") and r["as_owner"] != "Unknown":
                country_info += f"  |  AS: {_safe(r['as_owner'])}"
            row("Country:", country_info)

        pdf.set_x(14)
        for lbl, key, col in [
            ("Malicious",  "malicious",  (220, 38,  38)),
            ("Suspicious", "suspicious", (180, 120, 10)),
            ("Harmless",   "harmless",   (34,  150, 60)),
            ("Undetected", "undetected", (100, 100, 100)),
        ]:
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*col)
            pdf.set_fill_color(247, 249, 252)
            pdf.cell(22, 6, lbl + ":", fill=True, ln=False)
            pdf.set_text_color(50, 50, 50)
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(19, 6, str(r.get(key, "-")), fill=True, ln=False)
        pdf.ln(6)

        if r.get("recommendation"):
            pdf.set_fill_color(232, 240, 255)
            pdf.set_text_color(30, 70, 150)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_x(14)
            pdf.multi_cell(182, 5, _safe(r["recommendation"]), fill=True)

        if r.get("error"):
            pdf.set_text_color(180, 0, 0)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_x(14)
            pdf.cell(0, 5, f"Note: {_safe(r['error'])}", ln=True)

        pdf.set_text_color(40, 40, 40)
        pdf.ln(5)

    pdf.set_y(-18)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "Threat Intelligence Dashboard  |  VirusTotal API v3", align="C")

    return bytes(pdf.output())


if __name__ == "__main__":
    app.run(debug=True)
