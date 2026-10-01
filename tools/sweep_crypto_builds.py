#!/usr/bin/env python3
"""Measure build choices in a frozen private source copy; never alters wallet data."""
import hashlib,json,os,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PRIVATE=Path('/tmp/nucula-opt-20260915')
FROZEN=PRIVATE/'tune-repo'
DEFAULT={'BLOCKS':'11','TEETH':'6','WINDOW':'8','OPT':'Os','IRAM':'OFF','RAM_VERIFY':'OFF','RAM_SIGN':'OFF'}
VARIANTS=[
 ('07-comb2',{'BLOCKS':'2','TEETH':'5'}),
 ('08-window4',{'WINDOW':'4'}),
 ('09-window10',{'WINDOW':'10'}),
 ('10-window12',{'WINDOW':'12'}),
 ('11-window14',{'WINDOW':'14'}),
 ('12-secp-O2',{'OPT':'O2'}),
 ('13-secp-O3',{'OPT':'O3'}),
 ('14-secp-O2-window12',{'OPT':'O2','WINDOW':'12'}),
 ('15-secp-O3-window12',{'OPT':'O3','WINDOW':'12'}),
 ('16-secp-ram-verify',{'RAM_VERIFY':'ON'}),
 ('17-secp-ram-sign',{'RAM_SIGN':'ON'}),
 ('18-secp-iram',{'IRAM':'ON'}),
 ('19-mpi-iram',{}),
 ('20-combined-iram',{'IRAM':'ON'}),
]
if not FROZEN.exists():
 FROZEN.mkdir(mode=0o700)
 for name in ['main','components','managed_components']:
  shutil.copytree(ROOT/name,FROZEN/name,ignore=shutil.ignore_patterns('.git','.cache','build'))
 for name in ['CMakeLists.txt','sdkconfig','sdkconfig.defaults','partitions.csv','dependencies.lock']:
  shutil.copy2(ROOT/name,FROZEN/name)
 manifest={str(p.relative_to(FROZEN)):hashlib.sha256(p.read_bytes()).hexdigest() for p in FROZEN.rglob('*') if p.is_file() and p.name!='wifi_config.h'}
 (PRIVATE/'tune-source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
else:
 raise SystemExit('Frozen source already exists; do not overwrite an experiment')
for label,delta in VARIANTS:
 opts=DEFAULT|delta
 definitions=[f'-DNUCULA_SECP_{k}={v}' for k,v in opts.items()]+[f'-DNUCULA_MPI_IRAM={"ON" if label.startswith(("19-","20-")) else "OFF"}']
 log=PRIVATE/(label+'-build.log')
 print('BUILD',label,flush=True)
 with log.open('w') as out:
  result=subprocess.run(['idf.py']+definitions+['build'],cwd=FROZEN,stdout=out,stderr=subprocess.STDOUT)
 record={'label':label,'options':opts,'mpi_iram':label.startswith(('19-','20-')),'source_manifest_sha256':hashlib.sha256((PRIVATE/'tune-source-manifest.json').read_bytes()).hexdigest(),'build_ok':result.returncode==0}
 output=ROOT/'docs/crypto-research/device-results'
 if result.returncode:
  print('BUILD FAILED',label,log,flush=True)
  record['build_error_tail']=log.read_text()[-3000:]
 else:
  build=FROZEN/'build'; archive=PRIVATE/'builds'/label;archive.mkdir(parents=True,exist_ok=False)
  for name in ['nucula.bin','nucula.elf','nucula.map','compile_commands.json']:
   shutil.copy2(build/name,archive/name)
  record['app_bytes']=(build/'nucula.bin').stat().st_size
  record['app_sha256']=hashlib.sha256((build/'nucula.bin').read_bytes()).hexdigest()
  commands=['log i','bench mpi 79','bench verify 119 11','bench nutroot quick opt=3','bench','heap','tasks']
  args=[sys.executable,str(ROOT/'tools/crypto_device.py'),'--flash',str(archive/'nucula.bin'),'--log',str(PRIVATE/(label+'.log'))]
  for cmd in commands:args+=['--command',cmd]
  with (PRIVATE/(label+'-console.log')).open('w') as out:
   run=subprocess.run(args,cwd=ROOT,stdout=out,stderr=subprocess.STDOUT)
  record['device_ok']=run.returncode==0
  raw=(PRIVATE/(label+'.log')).read_text() if (PRIVATE/(label+'.log')).exists() else ''
  filtered=[s for s in raw.splitlines() if any(t in s for t in ['RESEARCH_COMMAND','bls_test:','nutroot:','crypto_test:','free:','block:','console ','stack-min','watchdog','FAILED'])]
  (output/(label+'.log')).write_text('\n'.join(filtered)+'\n')
  for line in filtered:
   if any(t in line for t in ['suite_verify','sign incl','schnorr verify','ECDH full','threshold 8','free:']):print(label,line,flush=True)
  if not record['device_ok']:
   (output/(label+'-build.json')).write_text(json.dumps(record,indent=2)+'\n')
   raise SystemExit('Device diagnostic failed; stopping sweep for inspection')
 (output/(label+'-build.json')).write_text(json.dumps(record,indent=2)+'\n')
print('BUILD SWEEP COMPLETE',flush=True)
