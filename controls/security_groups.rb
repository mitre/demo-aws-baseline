fixtures = {}
[
  'ec2_security_group_default_vpc_id',
  'ec2_security_group_default_group_id',
  'ec2_security_group_allow_all_group_id',
].each do |fixture_name|
  fixtures[fixture_name] = attribute(
    fixture_name,
    default: "default.#{fixture_name}",
    description: 'See ../build/ec2.tf',
  )
end

control "aws_security_groups-best-practice" do
  impact 0.7
  title "endure there are sg defined"
  desc "ensure there are sg defined"
  tag "nist": ["AC-6","Rev_4"]
  tag "severity": "high"
  tag "check": ""
  tag "fix": ""

  all_groups = inspec.aws_ec2_security_groups

  describe aws_ec2_security_groups do
    it { should exist }
    its('entries.count') { should be > 1 }
  end
  # You should be able to find a security group in the default VPC
  describe all_groups.where(vpc_id: fixtures['ec2_security_group_default_vpc_id']) do
    it { should exist }
  end
  # You should be able to find the security group named default
  describe all_groups.where(group_name: 'default') do
    it { should exist }
  end
end

control "cis_aws_foundations-4.1" do
  impact 0.7
  title "4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)"
  desc "Security groups provide stateful filtering of ingress/egress network
        traffic to AWS resources. It is recommended that no security group allows unrestricted
        ingress access to port 22."
  tag "nist": ["AC-6","Rev_4"]
  tag "severity": "high"

  tag "check": "
      1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
      2. In the left pane, click Security Groups
      3. For each security group, perform the following:
        1. Select the security group
        2. Click the Inbound Rules tab
        3. Ensure no rule exists that has a port range that includes port 3389 and
           has a Source of 0.0.0.0/0 Note: A Port value of ALL or a port range
           such as 1024-4098 are inclusive of port 3389. "
  tag "fix": "
      1. Login to the AWS Management Console at https://console.aws.amazon.com/vpc/home
      2. In the left pane, click Security Groups
      3. For each security group, perform the following:
        1. Select the security group
        2. Click the Inbound Rules tab
        3. Identify the rules to be removed
        4. Click the x in the Remove column
        5. Click Save "

  describe aws_ec2_security_group(fixtures['ec2_security_group_allow_all_group_id']) do
    it { should_not be_open_on_port(22) }
  end
end

control "cis_aws_foundations-4.2" do
  impact 0.7
  title "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  desc "VPC Flow Logs is a feature that enables you to capture information about the
        IP traffic going to and from network interfaces in your VPC.
        After you've created a flow log, you can view and retrieve its data in
        Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled
        for packet 'Rejects' for VPCs."
  tag "nist": ["AC-6","Rev_4"]
  tag "severity": "high"
  tag "check": "Via the Management Console:
      1. Sign into the management console
      2. Select Services then VPC
      3. In the left navigation pane, select Your VPCs
      4. Select a VPC
      5. In the right pane, select the Flow Logs tab.
      6. Ensure a Log Flow exists that has Active in the Status column."
  tag "fix": "Via the Management Console:
      1. Sign into the management console
      2. Select Services then VPC
      3. In the left navigation pane, select Your VPCs
      4. Select a VPC
      5. In the right pane, select the Flow Logs tab.
      6. If no Flow Log exists, click Create Flow Log
      7. For Filter, select Reject
      8. Enter in a Role and Destination Log Group"

  describe aws_ec2_security_group(fixtures['ec2_security_group_allow_all_group_id']) do
    it { should_not be_open_on_port(3389) }
  end
end
