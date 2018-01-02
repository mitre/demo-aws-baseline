
control "s3-objects-no-public-access" do
  impact 0.7
  title "Ensure there are no publicly accessable S3 objects"
  desc "Ensure there are no publicly accessable S3 objects"
  
  tag "nist": ["AC-6", "Rev_4"]
  tag "severity": "high"
  
  tag "check": ""Review your AWS console and note if any S3 objects are set to
                'Public'. If any objects are listed as 'Public', then this is
                a finding."

  tag "fix": "Log into your AWS console and select the S3 objects section. Select
              the objects found in your review. Select the permisssions tab for
              the objects and remove the Public access permission."

  my_buckets = inspec.aws_s3_buckets.buckets
  my_buckets.each do |bucket|
   describe aws_s3_bucket_objects(bucket) do
     # returns a true or false
     it { should_not have_public_objects }
     # returns a list of offenders if fails
     its('objects.public') { should cmp [] }
   end
  end
end
