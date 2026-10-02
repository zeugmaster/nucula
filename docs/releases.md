# Firmware releases

Firmware versions are independent of nucula.dev's website tags. The `Firmware`
workflow tests the USB console, tests the packager, builds with ESP-IDF **5.5.1**,
and checks the committed component lockfile on pull requests and main pushes.
The secp256k1 submodule is checked out recursively at its committed revision.

## Release a candidate

Commit the intended firmware, including USB setup support, then push a new tag:

```sh
git tag -a v0.1.0-rc.1 -m 'Firmware 0.1.0 release candidate 1'
git push origin v0.1.0-rc.1
gh run list --workflow firmware.yml
```

Accepted versions are `vX.Y.Z` and `vX.Y.Z-alpha.N`, `-beta.N`, or `-rc.N`.
The version without `v` is embedded in the application and must fit 31 bytes.
The workflow creates a **draft** with all six assets already attached:
`manifest.json`, `bootloader.bin`, `partition-table.bin`, `nucula.bin`,
`source.tar.gz`, and `SHA256SUMS`. Prerelease tags automatically set the prerelease
flag. A failed job never publishes a partial release; reruns do not overwrite an
existing release. Inspect an existing draft before deleting/recreating it.

Download the draft assets with `gh release download v0.1.0-rc.1`, check
`shasum -a 256 -c SHA256SUMS`, and test on a spare Rev-A board. Verify blank
installation, application update with wallet storage preserved, Wi-Fi save and
restart, automatic browser reconnection, and console commands. Record the
results and hardware limitations in the release notes. The OLED remains disabled
for bring-up. Automated tests cannot establish hardware acceptance.

After acceptance, publish the complete draft in GitHub Releases, or:

```sh
gh release edit v0.1.0-rc.1 --draft=false
```

The setup page discovers it within approximately ten minutes without a website
redeploy. Candidates appear only when users enable prereleases. A stable release
uses a fresh `v0.1.0` tag and build, follows the same checks, and becomes the
website's default after publication. Do not relabel candidate binaries as stable:
the embedded version must match the manifest and tag.

Enable **immutable releases** under repository Settings → General → Releases
before publishing. Build/upload into drafts, then publish: immutable releases
lock the assets and tag. Never move a published version tag or replace binaries.
Protect release-tag creation and workflow changes with repository rules appropriate
to the maintainers. Website authenticity depends on this repository and HTTPS.

## Manifest contract

Schema 2 targets `nucula-v2`, hardware `rev-a`, `ESP32-C3`, 4 MiB flash and USB
setup protocol 1. It names assets (never arbitrary download URLs), their lengths,
SHA-256 digests, and per-image MD5 digests used by the bootloader's verification.
It records the source commit and IDF version and includes corresponding source,
submodules, managed components, build config, and dependency lockfile. Personal
Wi-Fi headers, VCS metadata, and build caches are excluded.

`storage_schema: nucula-nvs-v1` is a compatibility promise: **every release using
this identifier must read and preserve wallet and Wi-Fi data written by every
other release using it, including newer versions**. It covers data encoding as
well as partition addresses. This permits selecting older versions within this
format. Changing persisted data incompatibly requires a new storage identifier,
changed partition-table bytes (for example a new partition label), a separately
reviewed migration strategy, and explicit website support. The changed table
also makes older installers refuse an update in ROM mode when device metadata
is unavailable. Merely
retaining the same partition table does not justify reusing the identifier.
The current browser rejects unknown storage formats and never erases NVS.

The packager validates the exact NVS/PHY/application partition table, executable
chip headers, app version, IDF version, and absence of the old compiled-credential
path. New boards receive separate bootloader/table/application images. Existing
boards with the matching layout receive only the application.

## Local validation

With ESP-IDF 5.5.1 activated, from this repository:

```sh
python scripts/test-console.py . "$IDF_PATH"
python scripts/test-package-release.py
idf.py -DPROJECT_VER=0.1.0-rc.1 build
python scripts/package-release.py build --commit "$(git rev-parse HEAD)"
```

Release builds must use a clean checkout with the committed sdkconfig.defaults;
local sdkconfig files can contain different developer settings. The workflow uses
a fresh checkout and publishes its generated sdkconfig inside the source archive.
`dist/` is ignored. Local packaging does not create or publish a GitHub Release.
