# Sample Test Data

This folder contains synthetic sample files used to manually exercise the
Sensitive Data Detection Engine, Risk Scoring Engine, and Policy Engine
without needing a real USB device or real sensitive data.

| File | Purpose | Expected Result |
|------|---------|------------------|
| `sample_sensitive.txt` | Contains PAN, Aadhaar, email, phone, and credit card patterns | HIGH sensitivity, risk score 100 (clamped), decision = BLOCK |
| `sample_clean.txt` | Contains no sensitive patterns | LOW sensitivity, risk score 0, decision = ALLOW |
| `sample_customers.csv` | Contains multiple rows of PAN/Aadhaar/email/phone | HIGH sensitivity, decision = BLOCK |
| `sample_app.log` | Contains an email, a phone number, and a PAN inside log lines | HIGH/MEDIUM sensitivity depending on order scanned |

## How to use

### Option A — Manual pipeline test (no real USB device required)

```bash
source venv/bin/activate
python - <<'PY'
from agent.scanner import SensitiveDataScanner
from agent.risk_engine import RiskEngine
from agent.policy_engine import PolicyEngine
import os

scanner = SensitiveDataScanner()
engine = RiskEngine()
policy = PolicyEngine()

path = "sample_data/sample_sensitive.txt"
result = scanner.scan_file(path)
assessment = engine.score(result, file_size_bytes=os.path.getsize(path))
decision = policy.evaluate(assessment)

print("Scan result:", result.to_dict())
print("Risk score:", assessment.risk_score, assessment.sensitivity)
print("Policy decision:", decision.decision, "-", decision.reason)
PY
```

### Option B — Real USB simulation

1. Insert a real USB drive while `run_agent.sh` is running.
2. Copy any file from `sample_data/` onto the USB drive.
3. Open the dashboard (`run_dashboard.sh`) and check the **File
   Activities**, **Risk Reports**, and **Incidents** pages — the copied
   file should appear with its computed risk score and (for the
   sensitive samples) a corresponding alert.

All values in these files are entirely synthetic and do not correspond
to any real person, organization, or financial instrument.
