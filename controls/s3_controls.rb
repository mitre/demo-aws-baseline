# research checking for 'http' proto from the world

control "s3buckets-public-access" do
  impact 0.7
  title "Ensure there are no publicly accessable S3 Buckets"
  desc "Ensure there are no publicly accessable S3 Buckets"
  tag "nist": ["CM-6", "Rev_4"]
  tag "severity": "high"
  tag "check": "review your AWS console and note if any S3 buckets are set to 'Public'. If any buckets are listed as 'Public', then this is a finding."
  tag "fix": "Log into your AWS console and select the S3 buckts section. Select the buckets found in your review. Select the permisssions tab for the bucket and remove the Public Access permission."

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
  desc "Ensure there are no Publicly Accessable S3 objects"
  tag "nist": ["CM-7", "Rev_4"]
  tag "severity": "high"
  tag "check": ""
  tag "fix": ""

  # test for any public objects - expected fail
  # test for any non-public objects - expected pass
end
