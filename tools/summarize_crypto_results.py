#!/usr/bin/env python3
"""Export measured rows with their command and diagnostic status intact."""
import csv,json,re
from pathlib import Path
root=Path(__file__).resolve().parents[1]
directory=root/'docs/crypto-research/device-results'
rows=[]
for path in sorted(directory.glob('[0-9][0-9]*.log')):
    command='';diagnostic=directory/(path.stem+'-diagnostics.json')
    status=json.loads(diagnostic.read_text()).get('diagnostics_ok') if diagnostic.exists() else None
    for line in path.read_text().splitlines():
        if line.startswith('RESEARCH_COMMAND '):command=line.removeprefix('RESEARCH_COMMAND ');continue
        content=re.sub(r'^[IWE] \(\d+\) \w+: ','',line)
        record={'experiment':path.stem,'command':command,'diagnostics_ok':status,'metric':'','iterations':'','mean_us':'','min_us':'','max_us':'','median_us':'','sample':'','source_line':line}
        m=re.match(r'^(.*?)\s+x(\d+)\s+mean\s+(\d+)\s+min\s+(\d+)\s+max\s+(\d+)\s+us$',content)
        if m:record.update(zip(['metric','iterations','mean_us','min_us','max_us'],m.groups()))
        else:
            m=re.match(r'^(.*?)\s+x(\d+)\s+mean\s+(\d+)\s+med\s+(\d+)\s+min\s+(\d+)\s+us',content)
            if m:record.update(zip(['metric','iterations','mean_us','median_us','min_us'],m.groups()))
            else:
                m=re.match(r'^(.*?)\s+x(\d+):?\s+(\d+)\s+us/op$',content)
                if m:record.update(zip(['metric','iterations','mean_us'],m.groups()))
                else:
                    m=re.match(r'^scale (cold|warm) sample=(\d+) time=(\d+) us valid=1$',content)
                    if m:record.update(metric='scale '+m[1],sample=m[2],mean_us=m[3],iterations=1)
                    else:
                        m=re.match(r'^(suite_verify cold n=\d+): (\d+) us, valid=1$',content)
                        if m:record.update(metric=m[1],mean_us=m[2],iterations=1)
        if record['metric']:rows.append(record)
destination=directory/'measurements.csv'
with destination.open('w',newline='') as output:
    writer=csv.DictWriter(output,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print(f'{len(rows)} measured rows written to {destination}; failed-run rows remain labeled, not silently discarded')
