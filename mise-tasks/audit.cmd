::MISE description="Run all security audit checks and save the output to audit-reports/"
@echo off
setlocal enabledelayedexpansion
rem Runs every check even when one fails, so a single run gives the full picture.
if not exist audit-reports mkdir audit-reports
set failed=0
for %%c in (audit:secrets audit:deps:python audit:deps:npm audit:sast:python audit:cdk-nag audit:licenses) do (
  set "name=%%c"
  set "report=audit-reports\!name::=-!.txt"
  echo === %%c ^(saving to !report!^)
  call mise run %%c > "!report!" 2>&1
  if errorlevel 1 (
    echo FAIL %%c
    set /a failed+=1
  ) else (
    echo PASS %%c
  )
)
echo.
echo !failed! check^(s^) failed. Reports are in audit-reports\.
if !failed! gtr 0 exit /b 1
