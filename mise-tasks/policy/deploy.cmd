::MISE description="Deploy or update the deployment policy stack"
::MISE depends=["policy:validate"]
@echo off
setlocal
rem moodle_role_name is configured once, in cdk.local.json, so read it from there
set "MOODLE_ROLE_NAME="
for /f "usebackq delims=" %%a in (`python -c "import json, pathlib; p = pathlib.Path('cdk.local.json'); c = json.loads(p.read_text(encoding='utf-8')) if p.exists() else {}; print(c.get('context', {}).get('moodle_role_name') or '')"`) do set "MOODLE_ROLE_NAME=%%a"
aws cloudformation deploy --template-file deployment-policies/deployment-policies.yaml --stack-name "%STACK_NAME%-deployment-policies" --parameter-overrides StackName="%STACK_NAME%" Qualifier="%QUALIFIER%" MoodleRoleName="%MOODLE_ROLE_NAME%" --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset
