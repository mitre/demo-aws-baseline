# research checking for 'http' proto from the world

control "s3buckets-public-access" do
  impact 0.7
  title "Ensure there are no publicly accessable S3 Buckets"
  desc "..."
  tag nist: "CM-7"

  regions = inspec.command("aws ec2 describe-regions --query 'Regions[].{Name:RegionName}' --output text").stdout.strip.lines

  regions.each do |region|

    buckets = inspec.command("aws --region #{region} s3api list-buckets --query 'Buckets[].Name' --output text").stdout.strip.split

    buckets.each do |bucket|
      next if bucket.nil?
      results = inspec.command("aws --region #{region} s3api get-bucket-acl --bucket #{bucket}  --output text ").stdout.strip
#require 'pry'; binding.pry;
      describe results do
        it { should_not include "AllUsers" }
     end

     describe results do	
        it { should_not include "AuthenticatedUsers" }
     end
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
