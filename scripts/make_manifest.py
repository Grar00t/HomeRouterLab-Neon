import hashlib, pathlib, sys

root = pathlib.Path(sys.argv[1])
skip_dirs = {".git", "reports", "__pycache__", ".pytest_cache", ".venv", "build", "dist"}
skip_files = {"SOURCE-MANIFEST.sha256"}
rows = []
for path in sorted(root.rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(root)
    if any(part in skip_dirs for part in rel.parts):
        continue
    if any(part.endswith(".egg-info") for part in rel.parts):
        continue
    if rel.name in skip_files or rel.suffix in {".pyc", ".log"}:
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows.append(f"{digest}  {rel.as_posix()}")
(root / "SOURCE-MANIFEST.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")
print(f"manifest: {len(rows)} files")