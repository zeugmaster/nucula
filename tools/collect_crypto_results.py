#!/usr/bin/env python3
"""Export only synthetic crypto measurements from private serial logs."""
import argparse,json,re
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('labels',nargs='+');a=p.parse_args()
root=Path(__file__).resolve().parents[1];private=Path('/tmp/nucula-opt-20260915')
out=root/'docs/crypto-research/device-results';out.mkdir(exist_ok=True)
for label in a.labels:
    if not re.fullmatch(r'[A-Za-z0-9_-]+',label):raise SystemExit('Invalid label')
    raw=(private/(label+'.log')).read_text(errors='replace')
    # Explicit line allowlist. WiFi configuration, boot dumps, wallet output
    # and all other traffic stay in the private log.
    lines=[line for line in raw.splitlines() if re.search(r'^(RESEARCH_COMMAND |[IWE] \(\d+\) (bls_test|nutroot|nutroot_current|crypto_test):|self-tests |free:|largest block:|min ever free:|name +prio|console +\d|IDLE +\d|wifi_drain +\d)',line)]
    (out/(label+'.log')).write_text('\n'.join(lines)+'\n')
    failures=[line for line in raw.splitlines() if re.search(r'\bFAILED\b|Guru Meditation|abort\(\) was called|Task watchdog|assert failed:|Rebooting|MPI option mask out of range',line)]
    (out/(label+'-diagnostics.json')).write_text(json.dumps({'label':label,'diagnostics_ok':not failures,'failures':failures,'raw_log_private':True},indent=2)+'\n')
    print(label,len(lines),'curated lines;',len(failures),'failure markers')
