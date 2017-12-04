# encoding: utf-8
#
=begin
-----------------
AWS-INSPEC-DEMO
Release Date: 2017-12-04
Version: 0.1
Publisher: MITRE
Source: MITRE.ORG
uri: http://mitre.org
-----------------
=end


control 'sg-1' do
  impact 1.0
  title 'Security Group: No ingress access to CIDR block 0.0.0.0/0'
  desc 'Security Groups must not allow inbound access from anywhere'

  tag nist: "AC-1"

  results = inspec.command("aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=* Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' --query 'SecurityGroups[*].{Name:GroupName}'").stdout.strip.chars.count

  describe results do
    it { should  <= 2 }
  end


end


# playbook to setup and config s3 bucket


control 's3bucket' do
  impact 0.7
  title 'test s3 bucket thing'
  desc "what we want to test on s3 buckets"

  tag nist: "AC-7"

  # perhaps this cli call is asking 'is the bucket publiclly accessable'
  # I think the cli call here would be 'has public set to yes'

  buckets = list

  buckets.each do | bucket |


  results = inspec.command('aws-cli s3bucket api query').stdout.strip

   describe results do
     its(content) { should_not cmp 'something' } # what text would be yes
   end
 end
