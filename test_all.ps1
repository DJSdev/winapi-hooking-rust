$targets = @(
    "message-box-a",
    "get-cursor-pos",
    "get-clipboard-data",
    "sleep",
    "is-debugger-present",
    "get-system-time-as-file-time",
    "exit-process",
    "create-file-w",
    "virtual-alloc-ex",
    "nt-query-system-information",
    "nt-open-process"
)

# Build the project first
Write-Host "Building project..."
cargo build -p rs-test
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed! Exiting." -ForegroundColor Red
    exit $LASTEXITCODE
}

$results = @()
$passedCount = 0
$failedCount = 0

$allowedExitCodes = @(0, 42069)

foreach ($target in $targets) {
    cargo build
    
    Write-Host "`n========================================"
    Write-Host "Testing target: $target"
    Write-Host "========================================"
    
    # Run the target. If some targets like message-box-a block waiting for user input,
    # the user will need to interact with them to continue to the next test.
    .\target\debug\rs-test.exe --target $target 1>$null
    
    $status = ""
    if ($LASTEXITCODE -notin $allowedExitCodes) {
        Write-Host "WARNING: Target $target exited with code $LASTEXITCODE" -ForegroundColor Red
        $status = "FAILED (Exit Code: $LASTEXITCODE)"
        $failedCount++
    } else {
        Write-Host "Target $target completed successfully." -ForegroundColor Green
        $status = "PASSED"
        $passedCount++
    }

    $results += [PSCustomObject]@{
        Target = $target
        Status = $status
    }
}

Write-Host "`n========================================"
Write-Host "               TEST REPORT              "
Write-Host "========================================"

foreach ($res in $results) {
    if ($res.Status -match "PASSED") {
        Write-Host "$($res.Target.PadRight(30)) : $($res.Status)" -ForegroundColor Green
    } else {
        Write-Host "$($res.Target.PadRight(30)) : $($res.Status)" -ForegroundColor Red
    }
}

Write-Host "----------------------------------------"
Write-Host "Total Tests : $($targets.Count)"
Write-Host "Passed      : $passedCount" -ForegroundColor Green
Write-Host "Failed      : $failedCount" -ForegroundColor Red
Write-Host "========================================"
