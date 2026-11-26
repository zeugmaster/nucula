#!/usr/bin/env python3
"""Build the real wallet against an in-memory mint/NVS with ASan and UBSan.
Requires IDF_PATH, Clang and the same OpenSSL/cJSON prefix as run_crypto_host.py.
"""
import argparse, json, os, subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--prefix', type=Path, default=Path('/opt/homebrew'))
a = p.parse_args()
repo = Path(__file__).resolve().parents[1]
work = a.output.resolve()
idf = Path(os.environ['IDF_PATH'])
subprocess.run(['python3', str(repo/'tools/run_crypto_host.py'), '--only', 'current',
                '--output', str(work), '--prefix', str(a.prefix)], check=True)
root = work/'source'
commands = json.loads((work/'commands.json').read_text())
common = commands[0][:commands[0].index('-c')]
common += ['-I'+str(root/'tools/wallet_test_shim')]
cbor = repo/'managed_components/espressif__cbor/tinycbor/src'
mbed = idf/'components/mbedtls/mbedtls'
common += ['-I'+str(cbor), '-I'+str(mbed/'include'), '-I'+str(mbed/'library')]
objects = [work/(name+'.o') for name in ['secp','precomputed_ecmult','precomputed_ecmult_gen',
                                       'blst','mpi','sha','bls_suite']]
for name in ['crypto','hex','nutroot','nutroot_prepare']:
    obj = work/('wallet_'+name+'.o')
    subprocess.run(common+['-c', str(root/'main'/(name+'.c')), '-o', str(obj)], check=True)
    objects.append(obj)
for src in [cbor/(name+'.c') for name in ['cborencoder','cborencoder_close_container_checked',
                                         'cborparser','cborparser_dup_string','cborparser_float']] + [mbed/'library/base64.c']:
    obj = work/(src.stem+'.o')
    subprocess.run(common+['-c', str(src), '-o', str(obj)], check=True)
    objects.append(obj)
cpp = ['wallet','wallet_recovery','nutroot_wallet','cashu_json','cashu_cbor','keyset','base64url','nut10','unit']
command = ['clang++']+common[1:]+['-std=c++17']
command += [str(root/'main'/(name+'.cpp')) for name in cpp]
command += [str(root/'tools/test_wallet_v3.cpp')]+[str(x) for x in objects]
command += ['-L'+str(a.prefix/'lib'),'-lcrypto','-lcjson','-o',str(work/'wallet')]
subprocess.run(command, check=True)
subprocess.run([str(work/'wallet')], check=True)
