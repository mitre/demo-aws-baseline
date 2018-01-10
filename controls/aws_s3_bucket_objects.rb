
control "s3-objects-no-public-access" do
  impact 0.7
  title "Ensure there are no publicly accessible S3 objects"
  desc "Ensure there are no publicly accessible S3 objects"
  tag "nist": ["AC-6", "Rev_4"]
  tag "severity": "high"

  tag "check": "Review your AWS console and note if any S3 bucket objects are set to
                'Public'. If any objects are listed as 'Public', then this is
                a finding."

  tag "fix": "Log into your AWS console and select the S3 buckets section. Select
              the buckets found in your review. For each object in the bucket
              select the permisssions tab for the object and remove
              the Public Access permission."

  my_buckets = aws_s3_buckets.table
  my_buckets.each do |bucket|
   describe aws_s3_bucket(bucket_name: bucket[:bucket_name]) do
     # returns a true or false
     it { should_not have_public_objects }
     # returns a list of offenders if fails
     its('public_objects') { should cmp [] }
   end
  end
end
