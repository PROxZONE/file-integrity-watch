#!/usr/bin/env python3
"""Create and verify a SHA-256 baseline for a local folder."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

IGNORED_DIRECTORIES = {'.git', '__pycache__', '.venv'}


def file_hash(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f'not a regular file: {path.name}')
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
        return digest.hexdigest()


def scan(root: Path, manifest_path: Path) -> dict[str, str]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('root must be a directory')
    excluded = manifest_path.resolve()
    files = {}
    def traversal_error(error):
        raise error
    for directory, folders, names in os.walk(root, followlinks=False, onerror=traversal_error):
        folders[:] = sorted(name for name in folders if name not in IGNORED_DIRECTORIES)
        for name in folders + sorted(names):
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError(f'symlink rejected: {path.relative_to(root).as_posix()}')
        for name in sorted(names):
            path = Path(directory) / name
            if path.resolve() == excluded:
                continue
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f'nonregular file rejected: {path.relative_to(root).as_posix()}')
            files[path.relative_to(root).as_posix()] = file_hash(path)
    return dict(sorted(files.items()))


def validate_manifest(data: dict) -> dict[str, str]:
    if not isinstance(data, dict) or data.get('schema_version') != 1 or data.get('algorithm') != 'sha256':
        raise ValueError('unsupported manifest schema or algorithm')
    files = data.get('files')
    if not isinstance(files, dict):
        raise ValueError('manifest files must be an object')
    for name, digest in files.items():
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name or name != path.as_posix():
            raise ValueError('manifest contains an unsafe path')
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('manifest contains an invalid SHA-256 digest')
    return files


def compare(expected: dict[str, str], actual: dict[str, str]) -> dict:
    before, after = set(expected), set(actual)
    changed = sorted(name for name in before & after if expected[name] != actual[name])
    added, missing = sorted(after - before), sorted(before - after)
    return {'ok': not (changed or added or missing), 'changed': changed, 'added': added,
            'missing': missing, 'unchanged_count': len(before & after) - len(changed)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('create', 'verify'))
    parser.add_argument('root', type=Path)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    try:
        actual = scan(args.root, args.manifest)
        if args.operation == 'create':
            data = {'schema_version': 1, 'algorithm': 'sha256', 'files': actual}
            args.manifest.parent.mkdir(parents=True, exist_ok=True)
            args.manifest.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
            print(json.dumps({'created': str(args.manifest), 'file_count': len(actual)}, indent=2))
            return 0
        expected = validate_manifest(json.loads(args.manifest.read_text(encoding='utf-8')))
        report = compare(expected, actual)
        print(json.dumps(report, indent=2))
        return 0 if report['ok'] else 1
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
