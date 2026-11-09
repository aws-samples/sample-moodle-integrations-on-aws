::MISE description="Bootstrap CDK toolkit stack"
::MISE depends=["site:build"]
@echo off

if defined POLICY_ARN (echo Using least privilege policy: %POLICY_ARN%) else (echo Using default AdministratorAccess policy - see README to create a least privilege policy and set POLICY_ARN)
if defined POLICY_ARN (cdk bootstrap --qualifier "%QUALIFIER%" --cloudformation-execution-policies "%POLICY_ARN%" --toolkit-stack-name "CDKToolkit-%STACK_NAME%") else (cdk bootstrap --qualifier "%QUALIFIER%" --toolkit-stack-name "CDKToolkit-%STACK_NAME%")
