::MISE description="Bootstrap the CDK toolkit stack with least privilege execution policies"
::MISE depends=["site:build"]
@echo off
setlocal
if /i "%ALLOW_ADMIN_EXECUTION_ROLE%"=="true" (
  echo WARNING: ALLOW_ADMIN_EXECUTION_ROLE=true. The CloudFormation execution role will have AdministratorAccess.
  cdk bootstrap --qualifier "%QUALIFIER%" --toolkit-stack-name "CDKToolkit-%STACK_NAME%"
  exit /b %errorlevel%
)
rem Run here rather than as a task dependency because mise reads its environment once at startup
call mise run policy:deploy
if errorlevel 1 exit /b 1
set "POLICY_ARNS="
for /f "usebackq delims=" %%a in (`aws cloudformation describe-stacks --stack-name "%STACK_NAME%-deployment-policies" --query "Stacks[0].Outputs[?OutputKey=='PolicyArns'].OutputValue" --output text`) do set "POLICY_ARNS=%%a"
if not defined POLICY_ARNS (
  echo Could not read the policy ARNs from the %STACK_NAME%-deployment-policies stack. Not bootstrapping. 1>&2
  exit /b 1
)
if "%POLICY_ARNS%"=="None" (
  echo Could not read the policy ARNs from the %STACK_NAME%-deployment-policies stack. Not bootstrapping. 1>&2
  exit /b 1
)
echo Using least privilege policies: %POLICY_ARNS%
cdk bootstrap --qualifier "%QUALIFIER%" --cloudformation-execution-policies "%POLICY_ARNS%" --toolkit-stack-name "CDKToolkit-%STACK_NAME%"
