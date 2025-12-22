# Sample Moodle Integrations on AWS

> **⚠️ DISCLAIMER**: This is sample code intended for demonstration and non-production use only. Review and adapt security configurations before deploying to production environments.

<!-- This repository provides sample implementations for the patterns described in the [AWS Guidance: Integrating Learning Management Systems (LMS) with AWS](<PLACEHOLDER_URL TODO:>). It demonstrates recommended practices for connecting Moodle with AWS services for a range of use cases. -->

## Overview

This project demonstrates multiple integration patterns for connecting Moodle with AWS:

- **Block Plugin**: AI-powered translation block using Amazon Bedrock 
- **Local Plugin**: Event observer that forwards Moodle events to AWS EventBridge for downstream processing
- **LTI Integration**: Learning Tools Interoperability (LTI) 1.3 integration for embedding AWS services in Moodle courses
- **Web Services API**: REST API integration for automated content indexing with vector embeddings

## Architecture

The solution includes:

- AWS CDK infrastructure (Python) for creating the necessary AWS resources
- React-based LTI frontend as a sample application
- Two Moodle plugins (AWS Events and AI Translator)

## Prerequisites

- Running Moodle instance (non production) 
- Moodle user with sufficient privileges to install plugins
- A standard Moodle user e.g. student

### Required Tools

- [mise](https://mise.jdx.dev/) - Development environment manager
  
  **macOS:**
  ```bash
  # Install mise
  brew install mise
  
  # Activate mise for current terminal session
  eval "$(mise activate bash)"    # for bash
  eval "$(mise activate zsh)"     # for zsh
  ```
  
  **Linux:**
  ```bash
  # Install mise
  curl https://mise.run | sh
  
  # Activate mise for current terminal session
  eval "$(mise activate bash)"    # for bash
  eval "$(mise activate zsh)"     # for zsh
  ```
  
  **Windows:**
  ```powershell
  # Install mise
  winget install jdx.mise
  
  # Activate mise for current PowerShell session
  mise activate pwsh | Out-String | Invoke-Expression
  ```
- Node.js 22 (managed by mise)
- Python 3.13 (managed by mise))
- AWS CLI (managed by mise on Mac and Linux. For Windows see [the installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).  This should be configured with appropriate credentials for the deployment account.
- AWS CDK (`npm install -g aws-cdk`)
- [Finch](https://github.com/runfinch/finch) or Docker running for container builds

**For Docker users**: Comment out the CDK_DOCKER line in `mise.toml`:
```toml
# CDK_DOCKER = "finch"
```

### AWS Requirements

1. **AWS Account**: You need a role (or less preferably IAM user) with sufficient permissions to deploy CDK stacks in the chosen region. 

   **Deployment Permissions**: The specific permissions required for deployment are documented in the [`deployment-least-privilege-policy.json`](./deployment-least-privilege-policy.json) file. This policy provides a reduced set of permissions focused specifically on the AWS services used by this stack, including:
   
   - CDK stack deployment and management
   - AWS service provisioning (Lambda, API Gateway, EventBridge, etc.)
   - Resource cleanup and updates
   
   This policy is significantly more restrictive than using the default `AdministratorAccess` and limits access to only the services needed by the CDK stack. You can use this policy document to create an IAM policy in your AWS account, or reference it when configuring deployment roles.

    **Note**: For production deployments, consider using more restrictive policies scoped to specific resource patterns and actions.

## Installation

### 1. Clone and Configure

```bash
git clone https://github.com/aws-samples/sample-moodle-integrations-on-aws.git 
cd sample-moodle-integrations-on-aws
mise trust
```

### 2. Configure Local Settings

**Configure AWS Region:**

Update the AWS region in `mise.toml` to match your chosen deployment region:

```toml
# Edit mise.toml and update the AWS_REGION line:
AWS_REGION = "your-preferred-region"
```

Copy the template and update with your values:

```bash
cp cdk.local.json.template cdk.local.json
```

**Configuration parameters:**

- **domain_name**: The domain name of your Moodle environment without the hostname (e.g., if your Moodle URL was `https://moodle.example.com`, `example.com` should be used). 
- **host_name**: Subdomain prefix for your Moodle instance (e.g., if your Moodle URL was `https://moodle.example.com`, `moodle` should be used).
- **moodle_role_name**: (Optional) Name of an existing IAM role for AWS-hosted Moodle (e.g., EC2 instance role, ECS task role, or EKS service account role). If provided, the EventBridge policy will be automatically attached to this role. If empty, you must manually configure authentication using IAM Roles Anywhere (recommended) or IAM user with access keys.

**Example for AWS-hosted Moodle:**
```json
{
  "context": {
    "domain_name": "example.com",
    "host_name": "moodle",
    "moodle_role_name": "MyEC2MoodleRole"
  }
}
```

**Example for non-AWS hosted Moodle:**
```json
{
  "context": {
    "domain_name": "example.com",
    "host_name": "moodle",
    "moodle_role_name": ""
  }
}
```

**IAM Permissions:**

The CDK deployment creates a managed IAM policy called `MoodleEventsIAMPolicy` with the minimum permissions required for EventBridge access. The policy configuration depends on your `moodle_role_name` setting:

- **AWS-hosted Moodle (EC2/ECS/EKS)**: If you specified a `moodle_role_name`, the deployment automatically attaches the `MoodleEventsIAMPolicy` to that existing role. Ensure the role name matches your EC2 instance role, ECS task role, or EKS service account role.

- **Non-AWS hosted Moodle**: If you left `moodle_role_name` empty, the `MoodleEventsIAMPolicy` is created but not attached to any role. You must configure authentication manually using one of the following approaches:

  **Option 1: IAM Roles Anywhere (Recommended)**
  
  Use AWS IAM Roles Anywhere to authenticate your Moodle instance without long-lived access keys:
  
  1. Set up IAM Roles Anywhere with your certificate authority
  2. Create an IAM role for IAM Roles Anywhere
  3. Attach the `MoodleEventsIAMPolicy` (created by this deployment) to your IAM Roles Anywhere role
  4. Configure your Moodle server to use the IAM Roles Anywhere credentials
  
  See [AWS IAM Roles Anywhere documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) for detailed setup instructions.

  **Option 2: IAM User with Access Keys (Use Only When Necessary)**
  
  If IAM Roles Anywhere is not feasible, create an IAM user with IP-restricted permissions:
  
  1. **Create an IAM user** (e.g., `MoodleEventsUser`) using the AWS Console or CLI
  2. **Create a custom policy** with IP address restrictions and attach it to your IAM user:
     
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": "events:PutEvents",
           "Resource": "arn:aws:events:REGION:ACCOUNT-ID:event-bus/moodle-events",
           "Condition": {
             "IpAddress": {
               "aws:SourceIp": [
                 "YOUR-MOODLE-SERVER-IP/32",
                 "YOUR-BACKUP-SERVER-IP/32"
               ]
             }
           }
         }
       ]
     }
     ```
     
     > **Note**: Use `/32` for specific IP addresses. If your Moodle environment frequently changes IP addresses (e.g. container based environment), you can use broader CIDR ranges like `192.168.1.0/24` or `10.0.0.0/16` to cover the relevant subnets, but be aware this reduces security by allowing access from a wider range of IP addresses.
  
  3. **Create access keys** for the IAM user and store them securely
  
  **⚠️ Security Requirements for Access Keys:**
  - Store access keys securely
  - Rotate access keys regularly 
  - Monitor access key usage through CloudTrail
  - Never commit access keys to version control
  - **Update IP addresses**: If your Moodle server IP addresses change, update the policy condition accordingly
  
  The IP address restriction in the policy above ensures that even if access keys are compromised, they can only be used from your authorized Moodle server locations.
  
### 3. Configure CDK Deployment Permissions (Optional)

By default, CDK uses the `AdministratorAccess` policy for CloudFormation execution. For enhanced security, you can optionally configure CDK to use least privilege permissions instead.

#### Default approach:

Leave `POLICY_ARN` empty in `mise.toml`:
```toml
POLICY_ARN = ""
```

This uses the default `AdministratorAccess` policy for CloudFormation execution.

#### Least privilege approach (recommended for production):

If you have an existing IAM policy with the minimum required permissions for CDK deployment, you can configure the deployment to use it:

1. **Create the required IAM policy:**
   Use the policy document provided in [`deployment-least-privilege-policy.json`](deployment-least-privilege-policy.json) to create an IAM policy with the minimum permissions required for this CDK deployment.

2. **Update mise.toml:**
   Edit the `mise.toml` file and update the `POLICY_ARN` line with your policy ARN:
   ```toml
   POLICY_ARN = "arn:aws:iam::YOUR-ACCOUNT-ID:policy/YOUR-POLICY-NAME"
   ```

**Security Note**: When `POLICY_ARN` is set, both your deployment role and the CloudFormation execution role will use the same least privilege policy. When empty, CDK uses `AdministratorAccess` for CloudFormation execution.

### 4. Initialize and Deploy

```bash
mise run init
mise run cdk:bootstrap
mise run cdk:deploy
mise run package
```

**Important**: Save the outputs from the `cdk:deploy` step, as these URLs and configuration values will be needed later when configuring the Moodle plugins.

## Available Commands

Managed through `mise.toml`:

### Development
- `mise run init` - Install all dependencies
- `mise run clean` - Remove build artifacts

### CDK Operations
- `mise run cdk:bootstrap` - Bootstrap CDK toolkit (uses `POLICY_ARN` if set)
- `mise run cdk:synth` - Synthesize and check for security issues
- `mise run cdk:deploy` - Deploy stack to AWS
- `mise run cdk:sync` - Watch and hot-reload changes
- `mise run cdk:destroy` - Destroy stack and cleanup

### Build
- `mise run site:build` - Build LTI frontend
- `mise run package` - Package all Moodle plugins
- `mise run events:package` - Package AWS Events plugin only
- `mise run aitranslator:package` - Package AI Translator plugin only

## Production Deployment Considerations

### Custom Domain for CloudFront Distribution

If the sample is being adapted for production deployments, it's strongly recommended to use a custom domain name for the LTI CloudFront distribution instead of the default CloudFront domain. This enables important security configurations:

**Security Benefits:**
- **SSL/TLS Policy Control**: Custom domains allow you to configure minimum SSL/TLS versions (e.g., TLS 1.2 or higher)
- **Certificate Management**: Use your own SSL certificates with proper certificate chains
- **Brand Consistency**: Use your organization's domain for better user trust



> **⚠️ Production Security**: Default CloudFront domains use shared SSL certificates and may not meet enterprise security requirements. Custom domains with proper SSL/TLS policies are essential for production deployments.

## Plugins
The deployment creates two plugin packages:
- `moodle/plugin/local/awsevents.zip` - AWS Events plugin
- `moodle/plugin/blocks/aitranslator.zip` - AI Translator block

### Enable Web Services

Before configuring plugins, enable Moodle's web services. This creates REST API endpoints that allow AWS services to authenticate and access Moodle resources. Specifically, this is required for:

- **AI Translator block**: User authentication via Moodle web service tokens
- **AWS Events plugin**: File indexing capabilities that allow AWS Lambda functions to retrieve course content and files from Moodle

1. Enable web services: Site Administration > Server > Web services > Overview
1. Enable REST protocol: Site Administration > Server > Web services > Manage protocols

> **⚠️ Security Note**: If web services are not currently enabled in your Moodle environment, make sure that you understand the risks of enabling these options and that you have appropriate controls and firewall rules in place to avoid unintended access to your Moodle environment. Web services create API endpoints that, if not properly secured, could expose sensitive data or functionality.

### AI Translator Block

Install the AI Translator block by navigating to Site Administration > Plugins > Install plugins and uploading the zip file.

#### Configure API Gateway

1. If not automatically redirected to the configuration page, navigate to: Site Administration > Plugins > Blocks > AI Translator
1. Configure:
   - **API Gateway URL**: The CloudFormation stack output starting with `MoodleAiTranslatorTranslateEndpoint` (e.g., `https://abc123.execute-api.us-west-2.amazonaws.com/v1/translate`)

#### Configure User Permissions

Create a custom role and external service for users who should have access to the AI Translator:

1. Create custom role: Site Administration > Users > Permissions > Define roles
   - Click `Add a new role`
   - Use role or archetype: `No role`
   - Short name: `aitranslatorrole`
   - Custom full name: `AI Translator Role`
   - Context types where this role may be assigned: `System`
   - Filter capabilities and allow:
     - `webservice/rest:use`
     - `moodle/webservice:createtoken`
   - Click `Create this role`
1. Assign role to users: Site Administration > Users > Permissions > Assign system roles
   - Select `AI Translator Role`
   - Add users who should have access to the translator e.g. a student user (not the Moodle administrator)
1. Create external service: Site Administration > Server > Web services > External services
   - Click `Add`
   - Name: `AI Translator Service`
   - **Short name: `ai_translator`** (⚠️ IMPORTANT: Must be exactly `ai_translator` - this is referenced from the plugin)
   - Enabled: ✓
   - Authorized users only: ✓
   - Click `Add service`
   - Click `Add functions`
   - Add function: `core_webservice_get_site_info`
   - Click `Add functions`
1. Authorize users: Site Administration > Server > Web services > External services
   - Click `Authorised users` for AI Translator Service
   - Add users who should have access e.g. a student user (not the Moodle administrator)

> **Note**: The `core_webservice_get_site_info` function is required for API Gateway authorization. This role grants only the minimum permissions required for the AI Translator to function, following the principle of least privilege.

#### Add Block to Course

1. Navigate to a course where you want to add the AI Translator block
1. Turn editing on
1. Click `Add a block` in the sidebar
1. Select `AI Translator`
1. The block will appear in the sidebar

#### Test Translation

1. Ensure you are logged in to Moodle with a user who has been authorized e.g. a student user (not the Moodle administrator)
1. In the AI Translator block, enter text in the input field
1. Click `Ask AI`
1. The translated text will appear below

**Verification:**

The block uses the user's Moodle web service token to authenticate with API Gateway, which validates the token against Moodle's web service API before invoking the translation Lambda function backed by Amazon Bedrock. Check CloudWatch Logs for the translate Lambda function to verify API calls.

> **Note**: Unlike the AWS Events plugin (below) which uses service credentials, the AI Translator block operates in the user's context. Each translation request is authenticated using a Moodle web service token generated for the logged-in user, ensuring user-level access control.

### AWS Events Plugin

Install the AWS Events plugin by navigating to Site Administration > Plugins > Install plugins and uploading the zip file.

> **Note**: The AWS Events plugin depends on the [local_aws plugin](https://moodle.org/plugins/local_aws) for AWS SDK support. You will be given the option to install this during the installation if not already installed.

#### Configure Event Forwarding

1. If not automatically redirected to the configuration page, navigate to: Site Administration > Plugins > Local plugins > AWS Events
2. Configure based on your authentication method:

**For AWS-hosted Moodle or IAM Roles Anywhere:**
- **AWS Authentication Method**: EC2 Instance Role
- **AWS Region**: Your deployment region (e.g., us-west-2)
- **Event Bus Name**: `moodle-events`

> **Note**: This configuration works for both AWS-hosted Moodle (EC2/ECS/EKS with `moodle_role_name` specified) and non-AWS hosted Moodle using IAM Roles Anywhere. IAM Roles Anywhere provides temporary credentials through the AWS credential chain, so the plugin treats it the same as an EC2 instance role.

**For non-AWS hosted Moodle with Access Keys (use only when necessary):**
- **AWS Authentication Method**: Access Keys
- **AWS Region**: Your deployment region (e.g., us-west-2)
- **AWS Access Key**: Your IAM user access key
- **AWS Secret Key**: Your IAM user secret key
- **Event Bus Name**: `moodle-events`

> **Security Note**: If using access keys, ensure they are stored securely, rotated regularly , and monitored through CloudTrail. Consider migrating to IAM Roles Anywhere for improved security. 

#### Configure Web Service API

Required for file indexing:

1. Create API user: Site Administration > Server > Web services > Create a specific user
   - Username: `index_files_api_user`
   - Password: Random password (doesn't need to be used again)
   - First name: `API`
   - Last name: `IndexFiles`
   - Email: unique email address
1. Create custom role: Site Administration > Users > Permissions > Define roles
   - Click `Add a new role`
   - Use role or archetype: `No role`
   - Short name: `webservicefileaccessrole`
   - Custom full name: `Web Service File Access Role`
   - Context types where this role may be assigned: `System`
   - Filter capabilities and allow:
     - `webservice/rest:use`
     - `moodle/course:view`
     - `moodle/course:viewhiddencourses`
   - Click `Create this role`
1. Assign role to user: Site Administration > Users > Permissions > Assign system roles
   - Select `Web Service File Access Role`
   - Add `API IndexFiles` user
1. Create external service: Site Administration > Server > Web services > External services
   - Click `Add`
   - Name: `Index Files Service`
   - Short name: `index_files`
   - Enabled: ✓
   - Authorized users only: ✓
   - Can download files: ✓
   - Click `Add Service`
   - Add function: 
      - Name: `core_course_get_contents`
      - Click `Add functions`
   - Authorize user: Site Administration > Server > Web services > External services
       - Select `Authorised users` against the IndexFiles service
       - Add the user `API IndexFiles` as an Authorised user
1. Create token: Site Administration > Server > Web services > Manage tokens
   - Click `Create token`
   - User: `API IndexFiles`
   - Service: `IndexFiles`
   - Valid until: unticked
1. In AWS Secrets Manager update the Secret value of the secret with a name starting with `MoodleEventHandlersMoodleTo` with the Token just generated

**Verification:**

After configuration, uploading a file to a Moodle course triggers a Lambda function that indexes it in the Bedrock Knowledge Base. Verify by checking the `moodle-plugins-MoodleDataSource` data source under the `moodle-plugins-MoodleFiles` Knowledge Base in the AWS Console.

## Sample LTI Tool

### Configure the Learning tools interoperability (LTI) tool

1. Configure the LTI tool: Site Administration > Plugins > Activity modules > Manage tools > Configure a tool manually
1. Enter details. Make sure to select LTI version as **LTI 1.3**. The **Tool URL**, **Public keyset**, and **Initiate login URL** can be found in the CloudFormation stack outputs

| Tool Parameter | Description | Cloudformation output |
|----------------|-------------|---------|
| Tool name | The name of the tool | N/A
| LTI Version | The version of LTI being used for signing messages and service requests should be set to LTI 1.3 | N/A |
| Tool URL | The URL of your tool's launch endpoint | LTIToolURL |
| Public keyset | The URL of an endpoint which will return a public key | LTIPublicKeyset |
| Initiate login URL | The URL of your tool's login endpoint | LTIInitiateLoginURL |
| Redirect URI (s) | List of URI (s) that Moodle can redirect to. You would usually add here at least your launch URI as Moodle redirects there as part of the handshake process | N/A |

1. Once the tool is created, you can click on the magnifiying glass icon to view the parameters generated by Moodle. Copy the **ClientID**.
1. On the AWS console, visit the Parameter store in the region where Moodle was deployed.
1. Modify the **/lti/client-id** parameter with the one copied above.
1. Back in Moodle, go to the course where you want to add the LTI tool
1. Enable the tool in the activity chooser: More > LTI External Tools > Show in activity chooser
1. Your tool should be available as an activity to add to a course.

> **Note**: This LTI tool is a sample implementation intended for demonstration purposes only. It demonstrates the LTI 1.3 authentication flow and integration patterns but does not provide functionality. Use this as a reference for building functional LTI tools.

## Project Structure

```
.
├── cdk/                    # CDK infrastructure code
│   ├── constructs/         # Reusable CDK constructs
│   └── cdk_stack.py        # Main stack definition
├── lambda/                 # Lambda function code
│   ├── delay/              # Event delay handler
│   ├── index_moodle_file/  # File indexing
│   ├── lti/                # LTI integration
│   ├── moodle_authorizer/  # API Gateway authorizer
│   └── translate/          # Translation service
├── lti_frontend/           # React LTI frontend
├── moodle/plugin/          # Moodle plugins
│   ├── blocks/             # AI Translator block
│   └── local/              # AWS Events local plugin
├── layers/                 # Lambda layers
├── app.py                  # CDK app entry point
├── cdk.json                # CDK configuration
└── mise.toml               # Task runner configuration
```

## Cleanup

To remove all deployed AWS resources:

```bash
mise run cdk:destroy
```

This command will:
- Delete the CloudFormation stack and all associated resources
- Remove Lambda functions, API Gateway, EventBridge bus and OpenSearch domain
- Clean up CloudWatch log groups

> **Note**: Some resources may incur costs until fully deleted. Verify deletion in the AWS Console.
