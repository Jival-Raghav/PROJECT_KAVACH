# check.ps1 — CI-style quality check script (Ruff lint + Pytest)
$ErrorActionPreference = "Stop"

Write-Host "==> Running Ruff Lint..." -ForegroundColor Cyan
& .\.venv\Scripts\ruff.exe check backend tests
if ($LASTEXITCODE -ne 0) {
    Write-Host "Ruff lint failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "==> Running Pytest Suite..." -ForegroundColor Cyan
& .\.venv\Scripts\pytest.exe -v tests/
if ($LASTEXITCODE -ne 0) {
    Write-Host "Pytest suite failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "==> All checks passed!" -ForegroundColor Green
exit 0
