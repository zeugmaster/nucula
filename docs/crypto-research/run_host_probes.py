#!/usr/bin/env python3
"""Reproduce arithmetic counts and compiler stack estimates, never MCU timings.

Requires Clang, OpenSSL headers/library, and cJSON headers/library. All modified
sources and binaries are confined to a temporary directory. The repository's
firmware sources are only read. These small probes are not a conformance suite.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError(f"Source changed; expected one occurrence of {old!r}")
    return source.replace(old, new, 1)


def run(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"Command failed: {shlex.join(args)}\n{result.stdout}\n{result.stderr}")
    return result


def host_probes(work, output, cc, prefix):
    blst = ROOT / "components/blst"
    secp = ROOT / "components/secp256k1/libsecp256k1"
    shutil.copytree(blst / "blst/src", work / "blst-src")
    vect = work / "blst-src/vect.h"
    vect.write_text(replace_once(vect.read_text(),
        "#if defined(__x86_64__) || defined(__aarch64__)",
        "#if 0 /* Research: use RV32 limbs on the host. */"))
    mpi = (blst / "port/blst_mpi.c").read_text()
    mpi = replace_once(mpi, "static void sw_mul_mont_n",
        "unsigned long long research_fp_ops;\nstatic void sw_mul_mont_n")
    mpi = replace_once(mpi, "    uint64_t limbx;",
        "    if (n == 12) research_fp_ops++;\n    uint64_t limbx;")
    (work / "mpi_count.c").write_text(mpi)
    # Quoted include searches beside the probe before project headers.
    shutil.copy2(HERE / "count_ops.c", work / "count_ops.c")
    common = [cc, "-O3", "-Wno-deprecated-declarations",
        "-I" + str(HERE / "sha_shim"), "-I" + str(prefix / "include"),
        "-I" + str(ROOT / "main"), "-L" + str(prefix / "lib")]
    bls_args = common + ["-D__BLST_NO_ASM__", "-D__BLST_PORTABLE__",
        "-I" + str(blst / "blst/bindings"), "-I" + str(blst / "port/include"),
        str(work / "blst-src/server.c"), str(work / "mpi_count.c"),
        str(work / "count_ops.c"), "-lcrypto", "-o", str(work / "bls_probe")]
    multi = work / "blst-src/multi_scalar.c"
    original_multi = multi.read_text()
    for name, chunk, force in [("chunk4", 4, False), ("chunk8", 8, False),
                               ("chunk11", 11, False), ("force-pippenger", 4, True)]:
        source = replace_once((ROOT / "main/crypto_bls.c").read_text(),
            "#define MILLER_CHUNK 4", f"#define MILLER_CHUNK {chunk}")
        (work / "crypto_bls.c").write_text(source)
        multi.write_text(replace_once(original_multi,
            "if ((npoints * sizeof(ptype##_affine) * 8 * 3) <= SCRATCH_LIMIT &&",
            "if (0 && (npoints * sizeof(ptype##_affine) * 8 * 3) <= SCRATCH_LIMIT &&")
            if force else original_multi)
        run(bls_args)
        result = run([str(work / "bls_probe")])
        (output / f"operation-counts-{name}.csv").write_text(result.stdout)
        print(f"BLS {name}: comparisons passed; {result.stderr.strip()}", flush=True)

    original = (ROOT / "main/nutroot.c").read_text()
    # Deliberately small experiments on well-formed fixtures. Full parser and
    # malformed-input equivalence must be established before any firmware port.
    early = original.replace("                satisfied++;",
        "                satisfied++;\n"
        "                if (satisfied >= parsed.n) { ok=1; goto out; }")
    fast = """    int candidate = n_sigs >= parsed.n;
    for (int i=0; i<parsed.n && candidate; i++) {
        secp256k1_xonly_pubkey pk;
        const cJSON *sig = cJSON_GetArrayItem(sigs,i);
        candidate = cJSON_IsString(sig) &&
            secp256k1_xonly_pubkey_parse(ctx,&pk,parsed.keys+i*33+1) &&
            sig_matches(ctx,&pk,sig->valuestring,digest);
    }
    if (candidate) {ok=1;goto out;}
"""
    variants = {"baseline": original, "early_success": early,
        "candidate_fastpath": replace_once(original,
            "    int satisfied = 0, verifies = 0;", fast + "    int satisfied = 0, verifies = 0;")}
    for name, source in variants.items():
        (work / "nutroot_probe_core.c").write_text(source)
        run(common + ["-O2", "-DENABLE_MODULE_SCHNORRSIG=1",
            "-DENABLE_MODULE_EXTRAKEYS=1", "-DECMULT_WINDOW_SIZE=8",
            "-I" + str(prefix / "include/cjson"),
            "-I" + str(secp / "include"), "-I" + str(secp / "src"),
            str(secp / "src/secp256k1.c"), str(secp / "src/precomputed_ecmult.c"),
            str(secp / "src/precomputed_ecmult_gen.c"), str(work / "nutroot_probe_core.c"),
            str(ROOT / "main/hex.c"), str(HERE / "nutroot_probe.c"),
            "-lcrypto", "-lcjson", "-o", str(work / "nutroot_probe")])
        result = run([str(work / "nutroot_probe")])
        (output / f"nutroot-{name}.csv").write_text(result.stdout)
        print(f"Nutroot {name}: valid/reversed/missing/duplicate checks passed", flush=True)


def cross_probes(work, output, compile_db):
    entries = json.loads(compile_db.read_text())
    rows = []
    for suffix, stem, values in [("/blst/src/server.c", "server", [None, 4, 11]),
                                ("/main/crypto_bls.c", "crypto_bls", [None, 8, 11])]:
        entry = next(x for x in entries if x["file"].endswith(suffix))
        for value in values:
            label = stem + ("-baseline" if value is None else
                           ("-limit" if stem == "server" else "-chunk") + str(value))
            args = shlex.split(entry["command"])
            args[args.index("-o") + 1] = str(work / (label + ".o"))
            args.append("-fstack-usage")
            if value is not None and stem == "server":
                args.append(f"-DMILLER_LOOP_N_MAX={value}")
            if value is not None and stem == "crypto_bls":
                copied = work / (label + ".c")
                copied.write_text(replace_once(Path(entry["file"]).read_text(),
                    "#define MILLER_CHUNK 4", f"#define MILLER_CHUNK {value}"))
                args[args.index(entry["file"])] = str(copied)
            run(args, cwd=entry["directory"])
            for line in (work / (label + ".su")).read_text().splitlines():
                if "blst_miller_loop_n\t" in line or "bls_verify_proofs.part" in line:
                    function, size, classification = line.split("\t")
                    rows.append([label, function.rsplit(":", 1)[-1], size, classification])
    with (output / "stack-frames.csv").open("w") as handle:
        writer = csv.writer(handle)
        writer.writerow(["variant", "function", "frame_bytes", "gcc_classification"])
        writer.writerows(rows)
    print("RV32 stack estimates recorded; no firmware linked or flashed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--prefix", type=Path, default=Path("/opt/homebrew"))
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--compile-db", type=Path,
                        help="Optional existing ESP-IDF compile_commands.json for RV32 stack estimates")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nucula-research-") as directory:
        work = Path(directory)
        host_probes(work, args.output, args.cc, args.prefix)
        if args.compile_db:
            cross_probes(work, args.output, args.compile_db)


if __name__ == "__main__":
    main()
