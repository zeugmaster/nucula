# blst (vendored)

BLS12-381 signature library for the Cashu keyset v3 (version byte `02`)
crypto suite.

- Upstream: https://github.com/supranational/blst
- Version: v0.3.16 (commit `e7f90de551e8df682f3cc99067d204d8b90d27ad`)
- Vendored subset: `src/` (minus `src/asm/` — rv32 uses the portable C path
  selected by `__BLST_NO_ASM__`), `bindings/blst.h`, `bindings/blst_aux.h`,
  `LICENSE` (Apache-2.0). Only `src/server.c` (the single-TU amalgamation)
  is compiled.

## Why vendored instead of a submodule

`no_asm.h` carries a local patch (see below) that rewrites `static`
functions — there is no link-time override seam, so the source itself must
change. A submodule + patch step would silently revert on
`git submodule update`, which is not an acceptable failure mode for
consensus-critical math. (secp256k1 is a submodule *because* it is
unpatched.) Re-diff against the upstream tag to review the local delta:

    git clone --depth 1 --branch v0.3.16 https://github.com/supranational/blst
    diff -r blst/src components/blst/blst/src

## Local patch: RSA/MPI hardware acceleration

`src/no_asm.h` routes 384-bit Fp Montgomery multiplication through the
ESP32-C3's RSA/MPI big-number peripheral — the technique from
https://github.com/zeugmaster/bls-bench (~4.4x on the full protocol; the
patched `no_asm.h` is copied verbatim from its vendored blst, comments
aside). Three functions change:

- `mul_mont_n` and `mul_mont_nonred_n` redirect to `mpi_mul_mont_n()`
  (`port/blst_mpi.c`). The peripheral always fully reduces, a strict
  superset of the lazy `nonred` contract.
- `sqr_mont_382x` is rewritten to keep every peripheral operand reduced
  into `[0, p)` — the original lazy form fed it a wrapped subtraction,
  violating the peripheral's `a*b < p*R` precondition.

The driver dispatches: 384-bit operands on the ESP32-C3 go to the
peripheral (single-reduction modexp early-exit trick, operand caching);
256-bit Fr and other targets take a verbatim copy of blst's portable
algorithm. See `port/include/blst_mpi.h` for the locking contract with
mbedTLS (shared peripheral).
