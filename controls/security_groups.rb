fixtures = {}
[
  'ec2_security_group_default_vpc_id',
  'ec2_security_group_default_group_id',
].each do |fixture_name|
  fixtures[fixture_name] = attribute(
    fixture_name,
    default: "default.#{fixture_name}",
    description: 'See ../build/ec2.tf',
  )
end

control "aws_security_groups-1" do
  impact 0.7
  title "endure there are sg defined"
  desc "ensure there are sg defined"
  tag "nist": ["CM-7","Rev_4"]
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

# TODO add titles, tags etc.
control "aws_ec2_security_group ingress_rules port 22 open" do
  describe aws_ec2_security_group(fixtures['ec2_security_group_allow_all_group_id']) do
    it { should_not be_open_on_port(22) }
  end
end

# TODO add titles, tags etc.
control "aws_ec2_security_group ingress_rules port 3389 open" do
  describe aws_ec2_security_group(fixtures['ec2_security_group_allow_all_group_id']) do
    it { should_not be_open_on_port(3389) }
  end
end
