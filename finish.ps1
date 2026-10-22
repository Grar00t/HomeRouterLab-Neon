$ErrorActionPreference = 'Stop'
$root = 'D:\projects\HomeRouterLab-Neon-20261022'
Set-Location -LiteralPath $root

function Assert-Exit([string]$Step) {
  if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit $LASTEXITCODE)" }
}

# 1) .gitattributes — LF for Python/MD, CRLF for cmd/ps1
$attrs = @"
# Default: LF
* text=auto eol=lf

# Windows entry points keep CRLF
*.cmd text eol=crlf
*.ps1 text eol=crlf
*.bat text eol=crlf

# Binary
*.png binary
*.jpg binary
*.zip binary
*.exe binary
*.b64 binary
"@
[IO.File]::WriteAllText("$root\.gitattributes", $attrs, (New-Object System.Text.UTF8Encoding($false)))

# 2) Remove v0.1.0 package + its 5 tests (they import home_router_lab)
Remove-Item -LiteralPath "$root\home_router_lab" -Recurse -Force -ErrorAction SilentlyContinue
foreach ($f in 'test_cli.py','test_core.py','test_render.py','test_reports.py','test_trace.py') {
  Remove-Item -LiteralPath "$root\tests\$f" -Force -ErrorAction SilentlyContinue
}

# 3) Move old acceptance script into legacy
if (Test-Path -LiteralPath "$root\scripts\acceptance.py") {
  Move-Item -LiteralPath "$root\scripts\acceptance.py" -Destination "$root\scripts\legacy\acceptance.py" -Force
}

# 4) Remove v0.1.0 entry point; move OFFER.md into docs
Remove-Item -LiteralPath "$root\home-router.cmd" -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath "$root\OFFER.md") {
  Move-Item -LiteralPath "$root\OFFER.md" -Destination "$root\docs\offer-v01.md" -Force
}

# 5) Verify: only 11 tests should remain
python -m pytest -q
Assert-Exit "pytest"

# 6) Regenerate manifest
python "$root\scripts\make_manifest.py" $root
Assert-Exit "make_manifest"

# 7) Commit and push
git add -A
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
  git -c user.name="Grar00t" -c user.email="Grar00t@users.noreply.github.com" commit -m "chore: remove superseded v0.1.0 package; v0.2.0 is the sole CLI" | Out-Null
}
git push
Assert-Exit "git push"

Write-Host "`n=== CLEANUP DONE ===" -ForegroundColor Green
python -m pytest -q
python -m homerouterlab --version