![File integrity watch](assets/banner.svg)

# File integrity watch

**Know what changed, and where.**

`Python 3.11+` · `Standard library` · `Offline` · `Synthetic examples`

Create a deterministic SHA-256 baseline, then compare the current folder with it. The report separates **changed**, **added**, and **missing** files and provides useful exit codes for local scripts.

| Exit code | Meaning |
| ---: | --- |
| `0` | Baseline created, or verification matched |
| `1` | Verification found changes |
| `2` | Invalid input, unsafe path, symlink, or I/O error |

## Scope and boundaries

- Files are hashed in chunks; the baseline has sorted relative paths.
- The chosen manifest is excluded from its own baseline.
- `.git`, `.venv`, and `__pycache__` folders are excluded.
- Symlinks encountered inside the tree and nonregular files are rejected.
- The intended platforms are Linux and macOS with a stable, quiescent folder tree.

A hash manifest is not a signed or tamper-proof record. Keep a trusted copy separately. This tool does not defend against an attacker who can modify both files and the manifest, or against adversarial directory changes during a scan. It is not a replacement for an endpoint-monitoring platform.

## Try a change

After creating the sample baseline, edit `examples/demo-tree/config.txt` and verify again. A mismatch should produce exit code `1`. Restore the sample afterwards with `git restore examples/demo-tree/config.txt`.

## Quick start

```bash
git clone https://github.com/PROxZONE/file-integrity-watch.git
cd file-integrity-watch
python3 integrity.py create examples/demo-tree --manifest out/baseline.json
python3 integrity.py verify examples/demo-tree --manifest out/baseline.json
```

## Example artifacts

See [`examples/`](examples/) for the sample inputs and [`sample-output/`](sample-output/) for generated results. Run the command above to reproduce them locally. Example IPs and domains are documentation data, not testing targets.

## Development

Python 3.11 or newer. No third-party packages are required.

```bash
python3 -m unittest discover -s tests -v
```

Use synthetic or appropriately sanitized data when contributing examples. Describe the observed behavior, the expected behavior, and a reproducible command in an issue.

## About this project

A learning project in [Divyansh Yadav’s cybersecurity portfolio](https://ceodivyansh.com). The examples are fictional and are not evidence of a completed client engagement or production deployment.
