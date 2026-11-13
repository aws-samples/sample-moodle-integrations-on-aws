::MISE description="Remove build artifacts and dependencies"
@echo off

if exist .venv rmdir /s /q .venv
if exist bin rmdir /s /q bin
if exist cdk.out rmdir /s /q cdk.out
if exist licenses-ts.csv del /q licenses-ts.csv
if exist licenses-python.txt del /q licenses-python.txt
if exist moodle\plugin\blocks\aitranslator.zip del /q moodle\plugin\blocks\aitranslator.zip
if exist moodle\plugin\local\awsevents.zip del /q moodle\plugin\local\awsevents.zip
if exist lti_frontend\node_modules rmdir /s /q lti_frontend\node_modules
if exist lti_frontend\dist rmdir /s /q lti_frontend\dist
for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d"
