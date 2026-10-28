$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python 3 is required.' }
}
& $pythonPath -m pip install --upgrade -r requirements.txt pyinstaller
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& $pythonPath -m PyInstaller --noconfirm --clean --windowed --onedir --name WebSentry --icon assets/websentry.ico --add-data 'assets;assets' main.py
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
$internalRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'dist\WebSentry\_internal'))
foreach ($name in @('icuuc.dll','icuin.dll')) {
    $candidate = Join-Path $internalRoot $name
    if ((Split-Path -Parent $candidate) -ne $internalRoot) { throw 'Unexpected DLL location.' }
    if (Test-Path -LiteralPath $candidate) {
        Rename-Item -LiteralPath $candidate -NewName ($name + '.disabled')
    }
}
Copy-Item -LiteralPath README.md -Destination dist/WebSentry/README.md
Copy-Item -LiteralPath THIRD_PARTY.md -Destination dist/WebSentry/THIRD_PARTY.md
Write-Host 'Ready: dist\WebSentry\WebSentry.exe. Keep the entire folder together.'
