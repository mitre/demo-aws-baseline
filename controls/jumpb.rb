
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

control "s3bucket" do
  impact 0.7
  title "test s3 bucket thing"
  desc "what we want to test on s3 buckets"

  tag "nist": "AC-7"

  buckets = inspec.command("aws s3api list-buckets --query 'Buckets[].Name' --output text").stdout.strip.lines

  buckets.each do |bucket|
    results = inspec.command("aws s3api get-bucket-acl --bucket #{bucket} --query Grants[?Grantee.Type==\'Group\'].[Grantee.URI,Permission] --output text | awk '{ print $1 }'").stdout.strip
     describe results do
       its(content) { should_not include %r{AllUsers|AuthenticatedUsers} }
     end
   end
