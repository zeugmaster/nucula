#!/usr/bin/env python3
"""Frozen post-pipeline configuration sweep on the identified C3."""
import hashlib,json,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];PRIVATE=Path('/tmp/nucula-opt-20260915');FROZEN=PRIVATE/'late-tune-repo'
BASE={'SECP_BLOCKS':'2','SECP_TEETH':'5','SECP_WINDOW':'12','SECP_OPT':'Os','SECP_IRAM':'OFF','SECP_HOT_IRAM':'ON','SECP_RAM_VERIFY':'OFF','SECP_RAM_SIGN':'OFF','MPI_IRAM':'ON','BLST_OPT':'O3','MPI_OPT':'O3','CRYPTO_LTO':'OFF'}
VARIANTS=[('26-small-ram-sign',{'SECP_RAM_SIGN':'ON'}),('27-blst-O2',{'BLST_OPT':'O2'}),('28-blst-Os',{'BLST_OPT':'Os'}),('29-crypto-lto',{'CRYPTO_LTO':'ON'}),('30-qio-window8',{'SECP_WINDOW':'8'}),('31-qio-window10',{'SECP_WINDOW':'10'}),('32-qio-comb11',{'SECP_BLOCKS':'11','SECP_TEETH':'6'}),('33-iram-off',{'MPI_IRAM':'OFF','SECP_HOT_IRAM':'OFF'}),('34-mpi-only-iram',{'SECP_HOT_IRAM':'OFF'}),('35-mpi-O2',{'MPI_OPT':'O2'}),('36-mpi-Os',{'MPI_OPT':'Os'})]
if FROZEN.exists():raise SystemExit('Frozen source exists; refusing to overwrite')
FROZEN.mkdir(mode=0o700)
for name in ['main','components','managed_components']:
 shutil.copytree(ROOT/name,FROZEN/name,ignore=shutil.ignore_patterns('.git','.cache','build'))
for name in ['CMakeLists.txt','sdkconfig','sdkconfig.defaults','partitions.csv','dependencies.lock']:
 shutil.copy2(ROOT/name,FROZEN/name)
manifest={str(p.relative_to(FROZEN)):hashlib.sha256(p.read_bytes()).hexdigest() for p in FROZEN.rglob('*') if p.is_file() and p.name!='wifi_config.h'}
manifest_text=json.dumps(manifest,indent=2)+'\n';(PRIVATE/'late-tune-source-manifest.json').write_text(manifest_text)
output=ROOT/'docs/crypto-research/device-results';(output/'late-tune-source-manifest.json').write_text(manifest_text)
print('FROZEN source recorded',flush=True)
for label,delta in VARIANTS:
 opts=BASE|delta;print('BUILD',label,flush=True)
 with (PRIVATE/(label+'-build.log')).open('w') as log:
  result=subprocess.run(['idf.py']+[f'-DNUCULA_{k}={v}' for k,v in opts.items()]+['build'],cwd=FROZEN,stdout=log,stderr=subprocess.STDOUT)
 record={'label':label,'options':opts,'source_manifest_sha256':hashlib.sha256(manifest_text.encode()).hexdigest(),'build_ok':result.returncode==0,'flash_mode':'QIO80 (bootloader25)'}
 if result.returncode:
  record['build_error_tail']=(PRIVATE/(label+'-build.log')).read_text()[-3000:]
 else:
  build=FROZEN/'build';archive=PRIVATE/'builds'/label;archive.mkdir(parents=True,exist_ok=False)
  for name in ['nucula.bin','nucula.elf','nucula.map','compile_commands.json']:
   shutil.copy2(build/name,archive/name)
  record['app_bytes']=(build/'nucula.bin').stat().st_size;record['app_sha256']=hashlib.sha256((build/'nucula.bin').read_bytes()).hexdigest()
  while not (PRIVATE/'allow-late-device').exists():time.sleep(1)
  commands=['log i','bench mpi 6735','bench verify 879 11','bench nutroot quick opt=15','selftest','heap','tasks']
  args=[sys.executable,str(ROOT/'tools/crypto_device.py'),'--flash',str(archive/'nucula.bin'),'--log',str(PRIVATE/(label+'.log'))]
  for command in commands:args+=['--command',command]
  with (PRIVATE/(label+'-console.log')).open('w') as log:run=subprocess.run(args,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
  record['device_ok']=run.returncode==0
  subprocess.run([sys.executable,str(ROOT/'tools/collect_crypto_results.py'),label],check=True)
  for line in (output/(label+'.log')).read_text().splitlines():
   if any(k in line for k in ['suite_verify n','sign incl','schnorr verify','ECDH full','threshold 8','free:']):print(label,line,flush=True)
 (output/(label+'-build.json')).write_text(json.dumps(record,indent=2)+'\n')
 if record.get('device_ok') is False:raise SystemExit('Device failed; stop and inspect before continuing')
print('LATE SWEEP COMPLETE',flush=True)
