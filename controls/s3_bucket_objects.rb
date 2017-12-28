
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
