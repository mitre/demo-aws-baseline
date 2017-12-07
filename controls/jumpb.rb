
control 'security_group-public-access-22' do
  impact 1.0
  title 'Security Group: No ingress access from CIDR block 0.0.0.0/0 to port 22'
  desc 'Security Groups must not allow inbound access from anywhere to port 22'
  tag nist: ""

  results = inspec.command("aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=* Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' --query 'SecurityGroups[*].{Name:GroupName}'").stdout.strip.chars.count

  describe results do
    it { should <= 2 }
  end
  
end

control "s3buckets-public-access" do
  impact 0.7
  title "Ensure there are no publicly accessable S3 Buckets"
  desc "..."
  tag nist: "CM-7"

  buckets = inspec.command("aws s3api list-buckets --query 'Buckets[].Name' --output text").stdout.strip.lines

  buckets.each do |bucket|
    results = inspec.command("aws s3api get-bucket-acl --bucket #{bucket} --query Grants[?Grantee.Type==\'Group\'].[Grantee.URI,Permission] --output text | awk '{ print $1 }'").stdout.strip
     describe results do
       it { should_not include "AllUsers" }
       it { should_not include "AuthenticatedUsers" }
     end
   end
end

control "s3bucket-public-objects" do
  impact 0.7
  title "Ensure there are no Publicly Accessable S3 objects"
  desc "..."
  tag nist: "CM-7"
  
  # test for any public objects - expected fail
  # test for any non-public objects - expected pass
  
end
