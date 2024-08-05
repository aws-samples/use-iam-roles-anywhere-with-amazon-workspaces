Use AWS IAM Roles Anywhere with Amazon WorkSpaces

Amazon WorkSpaces Personal provides a secure, persistent desktop computing environment in the cloud. However, natively, WorkSpaces does not support assuming IAM roles like EC2 instances. This can make it challenging to securely access AWS resources and services from within WorkSpaces while adhering to the principle of least privilege. Customers often ask if there is a method to configure WorkSpaces to use IAM Roles to issue temporary credentials. In this blog, we explain how you can configure WorkSpaces to use AWS IAM Roles Anywhere to obtain temporary security credentials.

This repository contains the PowerShell script for AWS Desktop and Application Streaming blog 'Accessing AWS resources from Amazon WorkSpaces using IAM Roles Anywhere'.
Please refer to the blog article for guidance on deploying the solution.

![image(1)](https://github.com/user-attachments/assets/c93923b7-1985-4d02-b47b-8247daadf098)


Once you have deployed the solution, you can run the PowerShell script provided in this repository to automate the credential configuration on the WorkSpaces.

This script performs the following tasks:

1. Defines a log function to write logs to a file named IAMRolesAnywhereScript.log in path $env:USERPROFILE.
2. Create a folder named UserCertificate in $env:USERPROFILE. Disables inheritance and set the NTFS permission for the current WorkSpace user on the folder.
3. Checks for existing .pfx and .pem certificates in the specified path and deletes them if present.
4. Exports the user's code-signing certificate to a .pfx file named pfxcertificate.pfx in the specified directory.
5. Converts the exported .pfx certificate to a .pem file named pemcertificate.pem in the specified directory.
6. Checks if the aws_signing_helper.exe tool is present in the specified awsSigningHelper path. If not, it downloads the tool from the provided URL.
7. Set the NTFS permission on private key for current user and disable inheritence on private key to secure the private key.
8. Generates the configuration for ~/.aws/config/ file

Instruction to use and update the script:

1. Replace the following variable in the PowerShell script:

$script:ProfileARN = "<REPLACE WITH PROFILE ARN>"
$script:RoleARN = "<REPLACE WITH IAM ROLE ARN>"
$script:TrustAnchorARN = "<REPLACE WITH TRUST ANCHOR ARN>"

2. The script needs to be run with elevated permission (Run as administrator) to allow setting the NTFS permission on the folder and the private key.
3. The IAM profile name configured in the ~/.aws/config file is iamrolesanywhere
4. The script doesn’t overwrite the existing configuration in the ~/.aws/config file which customer may have already configured. It adds the named profile section (https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html#cli-configure-files-format-profile) in the config file, replacing the variable with the actual value.

[profile iamrolesanywhere]
credential_process = $script:awsSigningHelperPath credential-process --certificate $script:PemCert --private-key $script:PemCert --profile-arn $script:ProfileARN --role-arn $script:RoleARN --trust-anchor-arn $script:TrustAnchorARN

5. Every time the script is run, the Set-AWSConfig function in the script runs a regex to replaces the above configuration in the ~/.aws/config file.
6. When running the command using AWS CLI or using AWS SDK please use the profile parameter to run the command or code. For example:

aws ec2 describe-instances —profile iamrolesanywhere

7. You can change the named profile in the script and specify your own profile name in Set-AWSConfig function. Modify the following lines in the script.

Line 321: [profile iamrolesanywhere]
Line 331: $newConfigContent = $existingConfigContent -replace '(?s)\[profile iamrolesanywhere\].?credential_process.?\n', ''

8. WorkSpaces users need to run this scripts every time the certificate expires (every 6 days). 


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

