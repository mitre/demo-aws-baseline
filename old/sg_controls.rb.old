
# Add attributes and arrays for accepted ports, protos and security_groups

control 'security_group-public-access-22' do
  impact 0.9
  title 'Security Group: No ingress access from CIDR block 0.0.0.0/0 to port 22'
  desc 'Security Groups must not allow inbound access from anywhere to port 22'
  tag "nist": ["AC-6","Rev_4"]
  tag "check": ""
  tag "fix": ""
  tag "severity": "high"

  results = inspec.command("aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=* Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' --query 'SecurityGroups[*].{Name:GroupName}'").stdout.strip.chars.count

  describe results do
    it { should <= 2 }
  end
end
