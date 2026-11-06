#!/usr/bin/env python3
"""Exercise packaging safeguards without ESP-IDF or hardware."""
import importlib.util
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('packager', Path(__file__).with_name('package-release.py'))
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)

class PackageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / 'build'
        self.source = self.root / 'source'
        self.build.mkdir()
        (self.source / 'main').mkdir(parents=True)
        (self.source / 'main/wifi.c').write_text('// Credentials only through NVS\n')
        (self.source / 'main/CMakeLists.txt').write_text('web_setup.cpp')
        (self.source / 'main/wifi_config.h').write_text('PRIVATE_CREDENTIAL')
        (self.source / 'sdkconfig').write_text('CONFIG_TEST=y\n')
        (self.build / 'project_description.json').write_text(json.dumps(dict(project_path=str(self.source), project_version='0.1.0-rc.1', target='esp32c3', project_name='nucula', config_file=str(self.source / 'sdkconfig'))))
        self.args = dict(flash_files={'0x0':'bootloader.bin','0x8000':'partition-table.bin','0x30000':'nucula.bin'}, extra_esptool_args={'chip':'esp32c3'}, flash_settings={'flash_size':'4MB'})
        self.write_args()
        image = bytearray(1024)
        image[0] = 0xe9
        struct.pack_into('<H', image, 12, 5)
        image[48:58] = b'0.1.0-rc.1'
        image[144:150] = b'v5.5.1'
        image[200:208] = b'@NUCULA '
        for name in ['bootloader.bin', 'nucula.bin']:
            (self.build / name).write_bytes(image)
        table = b''.join(struct.pack('<HBBII16sI', 0x50aa, kind, sub, offset, size, label, 0) for kind, sub, offset, size, label in [(1,2,0x9000,0x26000,b'nvs'), (1,1,0x2f000,0x1000,b'phy_init'), (0,0,0x30000,0x1d0000,b'factory')])
        (self.build / 'partition-table.bin').write_bytes(table)
    def write_args(self):
        (self.build / 'flasher_args.json').write_text(json.dumps(self.args))
    def package(self):
        packager.package(self.build, self.root / 'dist', 'a' * 40)
    def test_complete_package_excludes_credentials(self):
        self.package()
        dest = self.root / 'dist/0.1.0-rc.1'
        manifest = json.loads((dest / 'manifest.json').read_text())
        self.assertEqual(manifest['storage_schema'], 'nucula-nvs-v1')
        self.assertEqual([p['offset'] for p in manifest['parts']], [0, 0x8000, 0x30000])
        with tarfile.open(dest / 'source.tar.gz') as archive:
            self.assertNotIn('nucula/main/wifi_config.h', archive.getnames())
            self.assertIn('nucula/sdkconfig', archive.getnames())
        self.assertEqual(len((dest / 'SHA256SUMS').read_text().splitlines()), 5)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.package()
    def test_nvs_image_refused(self):
        self.args['flash_files']['0x9000'] = 'nvs.bin'
        self.write_args()
        with self.assertRaisesRegex(ValueError, 'wallet/NVS'):
            self.package()
    def test_unknown_layout_refused(self):
        (self.build / 'partition-table.bin').write_bytes(bytes(3072))
        with self.assertRaisesRegex(ValueError, 'Partition table'):
            self.package()
    def test_embedded_version_must_match(self):
        path = self.build / 'nucula.bin'
        image = bytearray(path.read_bytes()); image[48] = ord('9'); path.write_bytes(image)
        with self.assertRaisesRegex(ValueError, 'version does not match'):
            self.package()
    def test_compiled_credentials_refused(self):
        (self.source / 'main/wifi.c').write_text('#include "wifi_config.h"')
        with self.assertRaisesRegex(ValueError, 'credentials'):
            self.package()

if __name__ == '__main__':
    unittest.main()
