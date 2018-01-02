
control "s3bucket-public-objects" do
  impact 0.7
  title "Ensure there are no Publicly Accessable S3 objects"
  desc "Ensure there are no Publicly Accessable S3 objects"
  tag "nist": ["CM-7", "Rev_4"]
  tag "severity": "high"
  tag "check": ""
  tag "fix": ""

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
