param(
    [switch]$Help
)

if ($Help) {
    Write-Host "Project Context Bootstrap"
    Write-Host "Usage: .\bootstrap.ps1"
    Write-Host "Initializes a fresh agent session, validates the repository, and prints the current project context and next task."
    exit
}

$contextPath = ".\MASTER_PROJECT_CONTEXT\.context\canonical_context.md"
$handoffPath = ".\MASTER_PROJECT_CONTEXT\.context\handoff.md"

if (!(Test-Path $contextPath)) {
    Write-Host "[ERROR] Must be run from repository root. Canonical context file not found: $contextPath" -ForegroundColor Red
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "     ZERO-KNOWLEDGE SBOM VERIFICATION - BOOTSTRAP           " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host ">> CANONICAL CONTEXT" -ForegroundColor Yellow
$context = Get-Content $contextPath | Select-Object -First 10
$context | ForEach-Object { Write-Host $_ }
Write-Host "...(see $contextPath for full details)" -ForegroundColor DarkGray
Write-Host ""

Write-Host ">> CURRENT SESSION HANDOFF" -ForegroundColor Yellow
Get-Content $handoffPath | ForEach-Object { Write-Host $_ }
Write-Host ""

Write-Host ">> CRITICAL SAFETY RULES" -ForegroundColor Red
Write-Host "- NEVER reset/clean git or delete untracked/dirty files." -ForegroundColor Red
Write-Host "- NEVER expose .env contents, tokens, or private keys." -ForegroundColor Red
Write-Host "- NEVER modify circuits, VKs, or evidence without explicit authorization." -ForegroundColor Red
Write-Host "- ALWAYS read the canonical context files in MASTER_PROJECT_CONTEXT/." -ForegroundColor Red
Write-Host ""

Write-Host ">> REPOSITORY SNAPSHOT (scripts/project_context.py)" -ForegroundColor Yellow
if (Test-Path ".\scripts\project_context.py") {
    $snapshot = & python scripts/project_context.py --markdown
    $snapshot -split "`n" | Select-Object -First 15 | ForEach-Object { Write-Host $_ }
    Write-Host "...(output truncated for brevity. Run `python scripts/project_context.py --markdown` for full inventory)" -ForegroundColor DarkGray
} else {
    Write-Host "[WARNING] scripts/project_context.py not found." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Bootstrap complete. Please review the Next Action in the Handoff section above." -ForegroundColor Green
