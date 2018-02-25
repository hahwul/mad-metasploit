
require "open3"
require "msf/core"  

class MetasploitModule < Msf::Auxiliary
	
	include Msf::Auxiliary::Report
	def initialize 
		super(
			  'Name' => 'AWS S3 Public Bucket check', 
			  'Version' => '$Revision: 7243 $', 
			  'Description' => 'This module is check a AWS S3 public bucket.', 
			  'Author' => 'HaHwul', 
			  'License' => MSF_LICENSE
	)
	 #register_options("BUCKET_ADDRESS", self.class)   
	 register_options(
      [
        OptString.new('Target_Bucket', [true, 'Target bucket address > s3://bucket...', '']),
        OptString.new('AccessKey', [false, 'AWS access key', '']),
        OptString.new('SecretKey', [false, 'AWS secret key', '']),
        OptString.new('Region', [false, 'Region name', ''])
      ]
      )
	end
	
	def run 
	accesskey = datastore['AccessKey']
	secretkey = datastore['SecretKey']
	region = datastore['Region']
	bucket = datastore['Target_Bucket']
	print_status("Check a "+bucket+" bucket.")
	
	if datastore['AccessKey'].blank? && datastore['SecretKey'].blank? && datastore['Region'].blank?
		print_status("Load a AWS Client.")
	else
		print_status("Configure a AWS Client.")
		system("aws configure set accesskey #{accesskey}")
		system("aws configure set secretkey #{secretkey}")
		system("aws configure set region #{region}")
		print_status("Success Config data")
	end
	
	print_status("Send anonymous packet to "+bucket)
	query = "aws s3 ls #{bucket}"
	result = ""
	Open3.popen3(query) do | stdin, stdout , stderr| 
		while line = stderr.gets
			result = result + line
		end
	end
	
	result =  result.strip
	print_status("Log --> "+result)
	match_pattern = result.scan(/An error occurred/)
	if match_pattern.pop == "An error occurred"
		print_error("Not Vulnerable.")
	else
		print_good("Vulnerable!")
		print_good("  -> execute command a ' #{query} '")
	end
	end
end

