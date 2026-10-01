#!/usr/bin/env python3
"""Record a built experiment without putting firmware or credentials in git."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("label")
args = parser.parse_args()
if not re.fullmatch(r"[a-zA-Z0-9_-]+", args.label):
    raise SystemExit("Use a simple experiment label")
out = Path('/tmp/nucula-opt-20260915/builds') / args.label
out.mkdir(parents=True, exist_ok=False)
files = [ROOT/'CMakeLists.txt', ROOT/'sdkconfig.defaults', ROOT/'sdkconfig']
for directory in ['main', 'components/blst', 'components/secp256k1']:
    files.extend(p for p in (ROOT/directory).rglob('*')
                 if p.is_file() and '.git' not in p.parts and p.name != 'wifi_config.h'
                 and (p.suffix in {'.c','.cpp','.h','.cmake','.lf'} or p.name == 'CMakeLists.txt'))
manifest = {
    'label': args.label,
    'recorded_utc': datetime.now(timezone.utc).isoformat(),
    'git_head': subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip(),
    'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
    'app_sha256': hashlib.sha256((ROOT/'build/nucula.bin').read_bytes()).hexdigest(),
    'app_bytes': (ROOT/'build/nucula.bin').stat().st_size,
    'cmake_options': [line for line in (ROOT/'build/CMakeCache.txt').read_text().splitlines() if line.startswith('NUCULA_')],
}
with tarfile.open(out/'source.tar.gz','w:gz') as archive:
    for p in files:
        archive.add(p, arcname=str(p.relative_to(ROOT)))
shutil.copy2(ROOT/'build/bootloader/bootloader.bin', out/'bootloader.bin')
for name in ['nucula.bin','nucula.elf','nucula.map','compile_commands.json']:
    shutil.copy2(ROOT/'build'/name, out/name)
destination = ROOT/'docs/crypto-research/device-results'/(args.label+'-build.json')
destination.write_text(json.dumps(manifest,indent=2)+'\n')
print(f"Recorded {args.label}: {manifest['app_bytes']} application bytes, private build archive {out}")
