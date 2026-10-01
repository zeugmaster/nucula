#!/usr/bin/env python3
"""Reproduce portable RV32-layout crypto differential tests with ASan/UBSan."""
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True);p.add_argument('--prefix',type=Path,default=Path('/opt/homebrew'))
p.add_argument('--quick',action='store_true');p.add_argument('--only',choices=['bls','nutroot','current','schnorr','legacy'])
p.add_argument('--window-a',type=int,choices=[3,4,5],default=4)
p.add_argument('--cache-only',action='store_true',help='Focused BLS cache/chunk boundary regression set')
p.add_argument('--workspace-only',action='store_true',help='Focused BLS workspace/algorithm/allocation regression set')
p.add_argument('--y-cache-size',type=int,choices=[16,32,64],default=64)
a=p.parse_args();root=Path(__file__).resolve().parents[1];work=a.output.resolve();work.mkdir(parents=True,exist_ok=True)
source=work/'source';source.mkdir(exist_ok=False)
for directory in ['main','tools','components/blst','components/secp256k1','docs/crypto-research/sha_shim']:
    shutil.copytree(root/directory,source/directory,ignore=shutil.ignore_patterns('.git','wifi_config.h','__pycache__'))
root=source
(work/'source-sha256.json').write_text(json.dumps({str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in root.rglob('*') if f.is_file()},indent=2)+'\n')
ecmult=root/'components/secp256k1/libsecp256k1/src/ecmult_impl.h'
original=ecmult.read_text();assert 'define WINDOW_A 5' in original
ecmult.write_text(original.replace('define WINDOW_A 5',f'define WINDOW_A {a.window_a}'))
(work/'configuration.json').write_text(json.dumps({'forced_blst_limb_bits':32,'secp_window_a':a.window_a,'secp_window_g':12,'comb_blocks':2,'comb_teeth':5,'host_patch':'WINDOW_A in frozen upstream ecmult_impl.h only'},indent=2)+'\n')
shutil.copytree(root/'components/blst/blst/src',work/'blst-src',dirs_exist_ok=True)
v=work/'blst-src/vect.h';text=v.read_text();needle='#if defined(__x86_64__) || defined(__aarch64__)'
assert needle in text;v.write_text(text.replace(needle,'#if 0 /* compare the device 32-bit representation on the host */',1))
common=['clang','-O2','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-strict-aliasing','-Wno-deprecated-declarations','-D__BLST_NO_ASM__','-D__BLST_PORTABLE__']
common+=['-DNUCULA_Y_CACHE_SIZE='+str(a.y_cache_size),'-DNUCULA_Y_CACHE_AFFINE=1']
for inc in ['docs/crypto-research/sha_shim','main','components/blst/blst/bindings','components/blst/port/include','components/secp256k1/libsecp256k1/include','components/secp256k1/libsecp256k1/src','components/secp256k1/port/include']:
    common+=['-I'+str(root/inc)]
common+=['-I'+str(a.prefix/'include'),'-I'+str(a.prefix/'include/cjson')]
commands=[]
def run(args):
    commands.append([str(x) for x in args]);subprocess.run(args,cwd=root,check=True)
def obj(label,source,defs=[]):
    dest=work/(label+'.o');run(common+defs+['-c',str(source),'-o',str(dest)]);return dest
secp=[];bls=[]
if a.only!='bls':
    defs=['-DENABLE_MODULE_SCHNORRSIG=1','-DENABLE_MODULE_EXTRAKEYS=1','-DENABLE_MODULE_ECDH=1','-DECMULT_WINDOW_SIZE=12','-DCOMB_BLOCKS=2','-DCOMB_TEETH=5']
    secp=[obj('secp',root/'components/secp256k1/port/secp256k1_port.c',defs)]
    for name in ['precomputed_ecmult','precomputed_ecmult_gen']:
        secp.append(obj(name,root/f'components/secp256k1/libsecp256k1/src/{name}.c',defs))
if a.only not in ['nutroot','schnorr']:
    bls=[obj('blst',work/'blst-src/server.c'),obj('mpi',root/'components/blst/port/blst_mpi.c'),obj('sha',root/'components/blst/port/blst_sha.c')]
    support=work/'legacy_kdf_stub.c';support.write_text('#include <stdlib.h>\nint cashu_nut13_hmac(void){abort();}\n')
    bls_suite=obj('bls_suite',root/'main/crypto_bls.c');stub=obj('legacy_kdf_stub',support)
targets={
 'bls':([root/'tools/test_bls_optimization.c']+bls,['-DNUCULA_WORKSPACE_TEST'] if a.workspace_only else ['-DNUCULA_CACHE_TEST'] if a.cache_only else ['-DNUCULA_GLV_TEST'] if a.quick else []),
 'nutroot':([root/'tools/test_nutroot_optimization.c',root/'main/hex.c']+secp,[]),
 'schnorr':([root/'tools/test_schnorr_batch.c']+secp,[]),
 'legacy':([root/'tools/test_legacy_optimization.c',root/'main/crypto.c',root/'main/hex.c']+secp,[]),
}
if a.only not in ['nutroot','schnorr']:
    targets['current']=([root/'main/nutroot_current_test.c',root/'main/nutroot.c',root/'main/nutroot_prepare.c',root/'main/hex.c']+secp+bls+[bls_suite,stub],['-DNUCULA_HOST_TEST_MAIN'])
for name,(sources,defs) in targets.items():
    if a.only and a.only!=name:continue
    binary=work/name
    run(common+defs+[str(x) for x in sources]+['-L'+str(a.prefix/'lib'),'-lcrypto','-lcjson','-o',str(binary)])
    with (work/(name+'.log')).open('w') as log:
        commands.append([str(binary)]);result=subprocess.run([str(binary)],stdout=log,stderr=subprocess.STDOUT)
    print(name,(work/(name+'.log')).read_text(),flush=True)
    (work/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    if result.returncode:raise SystemExit(result.returncode)
