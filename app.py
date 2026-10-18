import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from flask import Flask, jsonify, request, render_template_string

from verislit import demo_data, llm, pipeline

app = Flask(__name__)


def load_samples():
    samples = {}
    for name in dir(demo_data):
        value = getattr(demo_data, name)
        if not name.startswith("_") and isinstance(value, str) and len(value) > 40:
            samples[name] = value
    return samples


SAMPLES = load_samples()


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/analyze")
def analyze():
    body = request.get_json(silent=True) or {}
    text = body.get("scan_text", "")
    if not body.get("consent"):
        return jsonify({"error": "Please confirm you have permission to analyze this scan."}), 400
    if not text.strip():
        return jsonify({"error": "Paste or load a scan first."}), 400
    if len(text) > 200000:
        return jsonify({"error": "Scan is too large."}), 400
    try:
        backend = llm.get_backend()
        report = pipeline.analyze(text, True, backend)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500


PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Verislit</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 12px;line-height:1.5}
textarea{width:100%;height:180px;font-family:monospace}
button{padding:8px 14px;margin:4px 4px 4px 0;cursor:pointer}
.card{border:1px solid #ccc;border-radius:8px;padding:10px;margin:10px 0}
.badge{background:#d8f5dc;border-radius:4px;padding:2px 6px;font-size:.85em}
.bad{background:#fde0e0}
pre{background:#f4f4f4;padding:8px;overflow:auto}
</style></head><body>
<h1>Verislit</h1>
<p>Paste Nmap output. Plain code finds and ranks issues, the AI only rewords them, and a Verifier checks every claim against the raw scan.</p>
<div id="samples"></div>
<textarea id="scan" placeholder="Paste Nmap output here"></textarea>
<p><label><input type="checkbox" id="consent"> I have permission to analyze this scan. I will not paste sensitive data (finding text is sent to an AI API).</label></p>
<button id="go">Analyze</button>
<button id="dl" disabled>Download JSON report</button>
<p id="msg"></p>
<div id="out"></div>
<script>
const SAMPLES = {{ samples|tojson }};
let lastReport = null;
const $ = id => document.getElementById(id);
function el(tag, text, cls){const e=document.createElement(tag); if(text!==undefined) e.textContent=text; if(cls) e.className=cls; return e;}

Object.keys(SAMPLES).forEach(name => {
  const b = el("button", "Load: " + name.replace(/_/g, " "));
  b.onclick = () => { $("scan").value = SAMPLES[name]; };
  $("samples").appendChild(b);
});

$("go").onclick = async () => {
  $("msg").textContent = "Analyzing...";
  $("out").innerHTML = "";
  try {
    const r = await fetch("/api/analyze", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({scan_text: $("scan").value, consent: $("consent").checked})});
    const data = await r.json();
    if (!r.ok) { $("msg").textContent = data.error || "Error"; return; }
    lastReport = data; $("dl").disabled = false; $("msg").textContent = "Done.";
    render(data);
  } catch (e) { $("msg").textContent = "Request failed: " + e; }
};

$("dl").onclick = () => {
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type:"application/json"});
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
  a.download = "verislit_report.json"; a.click();
};

function render(rep) {
  const out = $("out");
  const findings = rep.findings || [];
  const blocked = rep.blocked || [];
  const counts = {};
  findings.forEach(f => { const s = f.severity || "unknown"; counts[s] = (counts[s]||0) + 1; });
  out.appendChild(el("h2", "Summary"));
  out.appendChild(el("p", findings.length + " findings. " +
    Object.entries(counts).map(([k,v]) => k + ": " + v).join(", ")));
  findings.forEach(f => {
    const c = el("div", undefined, "card");
    c.appendChild(el("h3", "[" + (f.severity||"?").toUpperCase() + "] " + (f.title||f.id||"Finding")));
    const res = f.result || f.analysis || f;
    if (res.explanation) c.appendChild(el("p", res.explanation));
    if (res.risk) c.appendChild(el("p", "Why it matters: " + res.risk));
    if (Array.isArray(res.fix_steps)) { const ul = el("ul"); res.fix_steps.forEach(s => ul.appendChild(el("li", s))); c.appendChild(ul); }
    (f.evidence||[]).forEach(e => c.appendChild(el("pre", "Evidence: " + (e.quote||""))));
    const ok = res.verified !== false;
    c.appendChild(el("span", ok ? "Verified against raw scan" : "AI text rejected, rule text shown", ok ? "badge" : "badge bad"));
    out.appendChild(c);
  });
  out.appendChild(el("h2", "Run log"));
  out.appendChild(el("p", "Blocked AI claims: " + blocked.length));
  blocked.forEach(b => out.appendChild(el("pre", (b.finding_id||"") + ": " + (b.reason||JSON.stringify(b)))));
  const d = el("details"); d.appendChild(el("summary", "Raw JSON report"));
  d.appendChild(el("pre", JSON.stringify(rep, null, 2))); out.appendChild(d);
}
</script></body></html>"""


@app.get("/")
def index():
    return render_template_string(PAGE, samples=SAMPLES)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))