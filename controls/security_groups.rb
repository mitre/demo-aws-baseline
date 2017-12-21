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

puts aws_ec2_security_group("sg-f1888083").description.strip

control "aws_security_group" do
  describe aws_ec2_security_group("sg-f1888083") do
    it { should exist }
  end
end

control "aws_security_groups-1" do
  impact 0.7
  title "endure there are sg defined"
  desc "ensure there are sg defined"
  tag "nist": ["CM-7","Rev_4"]
  tag "severity": "high"
  tag "check": ""
  tag "fix": ""

  puts all_groups = aws_ec2_security_groups

  # You should always have at least one security group
  describe aws_ec2_security_groups do
    it { should exist }
  end

  describe aws_ec2_security_groups do
    its('entries.count') { should be > 1 }
  end

  # You should be able to find a security group in the default VPC
  describe all_groups.where(vpc_id: fixtures['ec2_security_group_default_vpc_id']) do
    it { should exist }
  end
  describe all_groups.where(vpc_id: 'vpc-12345678') do
    it { should_not exist }
  end

  # You should be able to find the security group named default
  describe all_groups.where(group_name: 'default') do
    it { should exist }
  end

  describe all_groups.where(group_name: 'no-such-security-group') do
    it { should_not exist }
  end
end
