
control "s3bucket-public-objects" do
  impact 0.7
  title "Ensure there are no Publicly Accessable S3 objects"
  desc "Ensure there are no Publicly Accessable S3 objects"
  tag "nist": ["CM-7", "Rev_4"]
  tag "severity": "high"
  tag "check": ""
  tag "fix": ""

  # #TODO need to decide which is the right approach
  # my_buckets = inspec.aws_s3_buckets(vpc: #{vpc_id})
  # *or*
  # my_buckets = inspec.aws_s3_buckets
  # my_buckets.each do |bucket|
  #   describe aws_s3_bucket_objects(bucket) do
  #     it { should_not have_public_objects }
  #     #TODO need to decide which approach makes the most sense
  #     its('objects.public') { should cmp [] }
  #     *or*
  #     its('objects.pubic') { should be nil }
  #     its('objects.private.count') { should be > 0 }
  #   end.only_if(bucket.entries.count > 0 )
  #   # MY FIRST INSTINCT: `bucket.objects.count`
  #   # MIDDLE GROUND?: make `objects` and alias for `entires`
  #   # or we could use `bucket.entries` like security_group does.
  #   # NOTE: Keeping things consistent across resources makes sense.
  #   # BUT: Only if we think it will help the user experience
  #   # the private var seems to be `bucket_objects` ...
  # end
  # # short and sweet version
  # my_buckets.each do |bucket|
  #  describe aws_s3_bucket_objects(bucket) do
  #    # returns a true or false
  #    it { should_not have_public_objects }
  #    # returns a list of offenders if fails
  #    its('objects.public') { should cmp [] }
  #  end
  # end
end
