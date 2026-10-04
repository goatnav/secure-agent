"""Run deterministic security regressions and publish measured pass/fail counts."""
import argparse
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

def main():
    p=argparse.ArgumentParser();p.add_argument("--go",default="go");p.add_argument("--python",default="python");args=p.parse_args()
    root=Path(__file__).resolve().parents[1];results=root/"results";results.mkdir(exist_ok=True)
    gateway=subprocess.run([args.go,"test","-json","./..."],cwd=root/"gateway",capture_output=True,text=True)
    events=[json.loads(line) for line in gateway.stdout.splitlines() if line.startswith("{")]
    checks=[e for e in events if "Test" in e and e.get("Action") in ("pass","fail","skip")]
    runtime=subprocess.run([args.python,"-m","pytest","-q","--junitxml",str(results/"runtime.xml")],cwd=root/"runtime",capture_output=True,text=True)
    summary={"at":datetime.now(timezone.utc).isoformat(),"mode":"deterministic mock + gateway enforcement",
             "gateway":{"passed":sum(e["Action"]=="pass" for e in checks),"failed":sum(e["Action"]=="fail" for e in checks)},
             "runtime":{},"success":gateway.returncode==0 and runtime.returncode==0,
             "interpretation":"Regression checks, not attack-success percentages. No unsecured baseline or live-model robustness claim."}
    xml=results/"runtime.xml"
    if xml.exists():
        suite=ET.parse(xml).getroot().find("testsuite")
        if suite is not None: summary["runtime"]={k:int(suite.get(k,"0")) for k in ("tests","failures","errors","skipped")}
    (results/"evaluation.json").write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
    if not summary["success"]:
        print(gateway.stdout,gateway.stderr,runtime.stdout,runtime.stderr);raise SystemExit(1)

if __name__=="__main__":main()
