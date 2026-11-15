from pathlib import Path
import tempfile
import unittest
from integrity import scan, compare, validate_manifest


class IntegrityTests(unittest.TestCase):
    def test_changed_added_and_missing(self):
        report = compare({'same': '1', 'changed': '2', 'gone': '3'}, {'same': '1', 'changed': '4', 'new': '5'})
        self.assertEqual(report['changed'], ['changed'])
        self.assertEqual(report['added'], ['new'])
        self.assertEqual(report['missing'], ['gone'])
        self.assertFalse(report['ok'])

    def test_empty_file_and_excluded_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'empty.txt').write_bytes(b'')
            manifest = root / 'baseline.json'
            manifest.write_text('{}')
            files = scan(root, manifest)
            self.assertEqual(list(files), ['empty.txt'])
            self.assertEqual(files['empty.txt'], 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_symlink_does_not_read_outside_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'root'
            root.mkdir()
            target = Path(directory) / 'outside.txt'
            target.write_text('outside')
            (root / 'link').symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'symlink rejected'):
                scan(root, root / 'baseline.json')

    def test_unsafe_manifest_paths_rejected(self):
        for path in ('../outside', '/etc/passwd', 'a/../b', 'a//b', 'a\\b'):
            with self.assertRaises(ValueError):
                validate_manifest({'schema_version': 1, 'algorithm': 'sha256', 'files': {path: '0' * 64}})

    def test_unsupported_manifest_and_bad_digest(self):
        for manifest in ({}, {'schema_version': 1, 'algorithm': 'sha256', 'files': {'x': 'bad'}}):
            with self.assertRaises(ValueError):
                validate_manifest(manifest)

    def test_git_directory_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.git').mkdir()
            (root / '.git' / 'config').write_text('local metadata')
            self.assertEqual(scan(root, root / 'baseline.json'), {})


if __name__ == '__main__':
    unittest.main()
