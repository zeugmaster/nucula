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

`no_asm.h` will carry a local patch (RSA/MPI hardware acceleration, ported
from https://github.com/zeugmaster/bls-bench) that rewrites `static`
functions — there is no link-time override seam, so the source itself must
change. A submodule + patch step would silently revert on
`git submodule update`, which is not an acceptable failure mode for
consensus-critical math. (secp256k1 is a submodule *because* it is
unpatched.) Re-diff against the upstream tag to review the local delta:

    git clone --depth 1 --branch v0.3.16 https://github.com/supranational/blst
    diff -r blst/src components/blst/blst/src
