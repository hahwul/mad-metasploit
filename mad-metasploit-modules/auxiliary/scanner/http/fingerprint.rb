require 'rex/proto/http'
require 'msf/core'
require 'thread'


class MetasploitModule < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	def initialize(info = {})


		super(	
			'Name'			=> 'HTTP Fingerprinter',
			'Description'		=> %q{ This module will attempt to fingerprint embedded HTTP(s) server(s) running on the port(s) specified, storing the findings
							for later use by another module.					
			},
			'Author' 		=> [ 'nebulus' ],
			'License'		=> MSF_LICENSE
			)

		register_options(
			[
				OptInt.new('MaxWait', [true, 'Longest amount of time to wait for response from server after successful connection', 30]),
				OptBool.new('SHOW', [false, 'Show detailed information when an unknown fingerprint encountered', true]),
				OptBool.new('LOGIN', [true, 'Try default usernames/passwords on successful fingerprint', false]),
				OptInt.new('MaxRedirect', [true, 'Maximum number of times to follow a request to redirect', 4]),
				OptString.new('FINGERPRINTS', [false, 'File containing fingerprints', File.join(Msf::Config.install_root, 'data', 'wordlists', 'http_default_fingerprints.csv')])
			], self.class)

		deregister_options('PASSWORD')		

	end

	def getURL(url, pieces = {}, opts = {})
	debug = 0
		return nil if url == nil
		print_status("URL #{url} / Pieces #{pieces.inspect}") if debug > 1
		if(pieces == nil)
			pieces = parseURL(url)
		end

		if(pieces.length == 0)
			pieces = parseURL(url)
		end
		ssl = false
		sslversion = datastore['SSLVersion']
		return nil if (not pieces.has_key?('vhost') and not opts.has_key?('ip') )
		if(not pieces.has_key?('port') )
			pieces['port'] = 80
		else
			print_status("Port was set for getURL (#{pieces['port']})...") if debug > 2
		end
		if(pieces.has_key?('proto') )
			if(pieces['proto'] == 'https')
				ssl = true
				sslversion = datastore['SSLVersion']
			else
				print_status("Protocol was #{pieces['proto']} but not SSL") if debug > 1
			end
		else
			print_status("No protocol sent to getURL...") if debug > 1
		end
				
		ip = (pieces.has_key?('vhost')) ? pieces['vhost'] : opts['ip']
		
		opts['uri'] = pieces['raw_path']	if(not opts.has_key?('uri') )
		opts['vhost'] = ip 			if(not opts.has_key?('vhost') )
		opts['ctype'] = 'text/html' 		if(not opts.has_key?('ctype') )
		opts['cookie'] = pieces['cookie'] 	if(pieces.has_key?('cookie') )
		opts['version'] = '1.0' 		if(pieces.has_key?('downgrade') )
		print_status("getURL: Trying #{url} with opts: #{opts.inspect}") if debug > 1

		begin
			lclient = Rex::Proto::Http::Client.new(ip,pieces['port'].to_i,nil,ssl,sslversion)
			request = lclient.request_raw(opts)
			result = lclient.send_recv(request, datastore['ConnectTimeout'].to_i)
#			select(nil,nil,nil,2)		# give it time to get buffer
			print_status("getURL response: #{result.inspect}") if debug > 1
			
			lclient.close
			return result
			rescue ::OpenSSL::SSL::SSLError => e
					return nil
			rescue Rex::ConnectionError, ::SocketError
				print_error("#{ip} Received a connection error...") if debug > 1
				return nil
			rescue Errno::ECONNRESET, Errno::ETIMEDOUT, Errno::ENOPROTOOPT
				return nil
			rescue ::Exception => e
				if(e.to_s == 'execution expired')
					vprint_error("#{ip} took too long to respond")
				else
					print_error("Error: '#{ip}' '#{e.class}' '#{e}' '#{e.backtrace}'")
				end
				return nil
		end

	end

	def parseURL(urlstring, current = nil)
	# take a url and parse it into its pieces
	debug = 0
		url = Hash.new
		url = current if current != nil
		raw_path = nil
		print_status("Parse URL called with #{urlstring.inspect} and current #{current.inspect}") if debug > 0
		if(urlstring[0,1] == '/' or urlstring !~ /^http/)
		# absolute path, non-uri
			raw_path = urlstring
		else
			pieces = urlstring.split('/')
			piece = pieces.shift
			piece.chop!
			url['proto'] = piece
			piece = pieces.shift
			piece = pieces.shift 	# need twice to get past //

			if(piece =~ /^(.+)\:(\d+)/)
				url['vhost'] = $1
				url['port'] = $2
			else
				url['vhost'] = piece
			end
			print_status("PIeces: #{pieces.length} " << pieces.inspect) if debug > 0
			if(pieces.length == 0)
				raw_path = '/'
			else
				raw_path = '/' << pieces.join('/')
			end
		end

		if(raw_path[raw_path.length-1, 1] != '/')
			print_status("Fixing up pieces where raw_path is #{raw_path}") if debug > 2
			pieces = raw_path.split('/')
			piece = pieces.pop
			print_status("pieces is now #{pieces.inspect}") if debug > 2
			url['file'] = piece
			url['path'] = pieces.join('/')
			url['path'] = '/' if url['path'] == ''
			url['raw_path'] = raw_path
		else
			print_status("Setting up url where path=raw_path #{raw_path}") if debug > 2
			url['raw_path'] = raw_path
			url['path'] = raw_path
		end
		print_status("Returning url of #{url.inspect}") if debug > 0
		return url
	end

	# Returns server token
	def server(resp)
		return resp.headers['Server']
	end

	#
	# Returns the title from the body of the response
	#
	def title(resp)
		title = nil		# will hold the <TITLE> contents, can occasionally hold more if <title></title> screwy
		if ( resp.body.length > 0 and resp.body.match(/<title.*\/?>(.+)<\/title\/?>/i) )
			title = $1
		end

		if title		# get rid of \n and limit \s and truncate if still too long
			title.gsub!(/\n/, '')
			title.gsub!(/\s{1,100}/, ' ')
			title.gsub!('&nbsp;', ' ')
			title.gsub!('&gt;', '>')
			title.gsub!('&lt;', '<')
			title.gsub!('&#032;', '')
			title = title[0,80] if title.length > 80 # probable bad regexp, truncate to 80
		end
		return title
	end

	# Returns the Basic Authentication Realm
	def realm(resp)
		return nil if auth(resp) == nil
		if(auth(resp) =~ /^basic realm\=\"(.+)\"$/i)
			return $1
		else
			return nil
		end
	end

	# Returns the WWW-Authenticate Token
	def auth(resp)
		return nil if not resp.headers.key?('WWW-Authenticate')
		return resp.headers['WWW-Authenticate']
	end

	# Returns the cookie
	def cookie(resp)
		return nil if not resp
		return nil if not resp.headers.key?('Set-Cookie')
		return resp.headers['Set-Cookie']
	end

	def resolveVHOST(host, how)
	debug = 0
		nm =  Net::DNS::Resolver.new
		n2 = nm.send(host,type=Net::DNS::A)
		return nil if n2.answer == nil
		n3 = n2.answer.to_s

		return nil if n3 == nil
		if(how.downcase == 'ptr')
			n3.match(/\s+IN\s+PTR\s+(\S+)\.$/)
			return $1
		elsif(how.downcase == 'a')
			n3.match(/\s+IN\s+A\s+(\S+)$/)
			return $1
		end

		return nil

	end

	def detectRedirect(response, url)
	# given the response and the path (need it for relational paths), detect redirects and return the uri needed
	debug = 0

		urlstring = ''
		if(url.kind_of? String)
			print_status("url was string of '#{url}' not hash...") if debug > 0
			urlstring = url
			url = Hash.new
			url = parseURL(urlstring, nil)
			url['redirect'] = false
		else
			urlstring = "#{url['proto']}://#{url['vhost']}:#{url['port']}#{url['raw_path']}"
		end

		if(response == nil or url == nil)
			url['redirect'] == false
			return url
		end

		# set redirect to false so will know if have to try again
		if(not url.has_key?('redirect') )
			url['redirect'] = false
		else
			url['redirect'] = false
		end

		lines = response.body.split(/\r?\n/)

		if((300..309).include?(response.code) and response.headers.has_key?('Location'))
		# HTTP server through code indicates a redirect to header['Location']
			print_status("redirect code: #{response.headers['Location']}") if debug > 2
			url['redirect'] = true

			if(response.headers['Location'][0,1] == '/')
			# absoute path
				url['raw_path'] = response.headers['Location']
			elsif(response.headers['Location'] !~ /^http/)
			# relative path
				url['raw_path'] = "#{url['raw_path']}" << response.headers['Location']
			else
			# uri path
				url = parseURL(response.headers['Location'], url)
			end
			print_status("redirect code based pieces now: #{url.inspect}") if debug > 0
		elsif(response.headers.has_key?('Refresh') )
		# HTTP server used Refresh: token 
			if(response.headers['Refresh'] =~ /(\d+)\;\s*URL\=(\S+)$/i) 
				delay = $1.to_i
				new_location = $2
				delay = 1 if(delay > 2)
				select(nil,nil,nil,delay)
				if ( new_location == url['raw_path'] or "/#{new_location}" == url['raw_path'] )
				# don't get caught refreshing to same URL
					url['redirect'] = false
					return url
				end

				new_location = "#{url['raw_path']}#{new_location}" if(new_location[0,1] != '/')
				url['redirect'] = true
				url = parseURL(new_location, url)
				print_status("HTTP token redirect based pieces now: #{url.inspect}") if debug > 0
			end
		elsif(response.body =~ /\<meta http\-equiv\=\"Refresh\"\s+content\=\"(\d+)\;\s*URL\=(\S+)\"\/*\>/i )
		# web page content indicates in HTML header to refresh
			print_status("Match #{$1} and '#{$2}' as new_location for '#{response.body}'") if debug > 0
			delay = $1.to_i
			new_location = $2
			new_location.gsub!(/\'/, '')
			new_location.gsub!(/\"/, '')

			if(response.body.match(/\<noscript\>.*\<META HTTP-EQUIV\=\"Refresh\" .+\>.\<\/noscript\>/) )
			# don't get caught in no-script
				url['redirect'] = false
				return url
			end
			
			if(new_location == url['raw_path'] or "/#{new_location}" == url['raw_path'])
			# don't get caught refreshing to same URL
				url['redirect'] = false
				return url
			end
			delay = 1 if(delay > 2)
			select(nil,nil,nil,delay)
			new_location = "#{url['raw_path']}#{new_location}" if(new_location[0,1] != '/' and new_location[0,4] != 'http')
			url['redirect'] = true
			url = parseURL(new_location, url)
				print_status("HTML refresh redirect based pieces now: #{url.inspect}") if debug > 0

		elsif(server(response) =~ /Microsoft-IIS/ and title(response) =~ /The page must be viewed over a secure channel/)
		# lazy IIS won't always auto redirect, this detects error message and handles it for you
			url['port'] = 443
			url['ssl'] = true
			url['path'] = "/"
			url['raw_path'] = "/"
			url['redirect'] = true
		elsif(response.code == 400 and response.message.to_s.downcase == "bad request" and response.body =~ /\<h1\>Bad Request \(Invalid Hostname\)/i and
			(url['vhost'] =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ or url['vhost'] == nil) ) 
			url['vhost'] = resolveVHOST(url['vhost'], 'ptr')
			url['redirect'] = true
#			print_error("#{url['vhost']} requires DNS resolution to complete redirection")
			url['redirect'] = false
		elsif(response.code == 400 and response.message.to_s.downcase == "bad request")
			url['downgrade'] = true
			url['redirect'] = true
		end
		print_status("Leaving checkRedirect with #{url.inspect}") if debug > 0
		return url
	end

	def doRedirect(pieces)

		return nil if not pieces
		if(pieces.has_key?('redirect'))
			return nil if(pieces['redirect'] == false)
		end

		count = 0
		response = nil
		
		while (count < datastore['MaxRedirect']) 
			request = "#{pieces['proto']}://#{pieces['vhost']}:#{pieces['port']}#{pieces['raw_path']}"
			response = getURL(request, pieces)
			count = count + 1
			pieces = detectRedirect(response, pieces)
			break if pieces['redirect'] == false
		end
		return response, pieces
	end

	def get_details(name)
	debug = 0
		info = 	File.join(Msf::Config.install_root, 'data', 'wordlists', 'http_default_devices.csv')
		fd = CSV.foreach(info) do |line|
			next if line[0].match(/^#/)
			if(line.length != 6)
				print_error("Malformed line in CSV file: #{line}")
			end
			print_status("Comparing #{name} to #{line[0]}") if debug > 1
			if(line[0] == name)
				return line
			end
		end
		return nil
	end


	def fingerprint(response, pieces)
	# fingerprint the server
	# response = HTTPResponse Object
	# pieces = pieces of the URL that may be helpful

	# returns a struct, with manufacturer, type of device, subtype of device, and a name, minimally
	#	the name is used by other functions to set the appropriate urls/users/conditions to test for default usernames/passwords

	# Adding fingerprints
	# 	Minimally need server and title, but would like realm and something unique in body for better matches, unless title/server are unique enough already

	debug = 0
		cookie = cookie(response)
		ip = vhost = pieces['vhost']
		path = pieces['raw_path']

		print_status("#{ip} Entering Fingerprint #{path}, #{ip}") if debug > 1
		return nil if not response
		body = response.body
		body.gsub!(/[\n\r]/, '')	# strip CRLF
		server = server(response)
		realm = realm(response)
		title = title(response)
		fprint = Hash.new {}		# will be returned as struct holding Fingerprint info



		## Local variables all set, lets start fingerprinting
		print_status("#{ip} Fingerpint: Server: '#{server}' Title: '#{title}' Realm: '#{realm}' Body: '#{body[0,2048]}'") if debug > 0

		# load up fingerprints
		fingerprints = 	datastore['FINGERPRINTS']
		fd = CSV.read(fingerprints)
		name = nil
		fd.each do |fp|
			next if(fp[0] =~ /^#/)
			if(fp.length != 12)
				# debug check for incomplete bruteforce length
				print_error("WARNING: fingerprint has " << fp.length.to_s << " members (#{fp.inspect})")
			end
			i=0
			good = true
			while(i < fp.length - 2 and good)
				break if good == false
				val = fp[i]			# pattern read in
				re = fp[i+1].to_i		# how to check for match
				if val == 'NA'
					i += 2
					next
				end

				if(val != nil)
					val.gsub!('\x2c', ',')
				end
				s = ''

				s = val.split('\x00') if val != nil
				val = ' ' if val == nil

				comp = String.new('')
				case i 
					when 0
						comp = server
					when 2
						comp = realm
					when 4
						comp = path
					when 6 
						comp = title
					when 8
						comp = body
				end # case i
				comp = ' ' if(comp == nil)
				if( (re == 0 and comp != val) or
					(re == 1 and not comp.match(val)) or (re == 2 and not comp.match(/#{val}/i) ) or 
					(re == 3 and not comp.match(/#{s[0]}/) and not comp.match(/#{s[1]}/)) or
					(re == 4 and comp.match(val) )
				)
					good = false
				end
				i += 2
			end # end while i < fp.length - 2


			if(good)
				print_status("Have a good match on #{fp.inspect}") if debug > 1
				name = fp[10]
				fprint['Variant'] = fp[11]
				break
			end
		end #fd.each

		body.tr!("\n", ' ') if body
		title.tr!("\n", ' ') if title
		fprint['Server'] = server
		fprint['Title'] = title
		fprint['Body'] = body[0,512]
		fprint['Realm'] = realm
		if(name == nil)
			proto = pieces['proto']
			out = "#{proto}://#{ip}#{path} "
			if(datastore['SHOW'] == true)
				if("#{server}" == '' and "#{title}" == '' and "#{body}" == '' and "#{realm}" == '')
					print_error("#{ip}, #{out} - Server up but no information available to fingerprint with...")
				elsif(response.code < 500 and response.code != 404 ) 
					print_status("==> #{out} New Fingerprint: Server=>#{server},Title=>#{title},Realm=>#{realm},Body=>"+ body[0,2048])
				end
				return nil
			end
			
		else
			print_status("Getting details for fingerprint #{fprint.inspect}") if debug > 1
			t = get_details("#{name}")
			fprint['Name'] = name
			if(t != nil)
				fprint['Manufacturer'] = t[1]
				fprint['Type'] = t[2]
				fprint['SubType'] = t[3]
			else
				print_error("#{ip} For '#{name}', I couldn't find any details")
			end
		end
		print_status("Returning fingerprint of #{fprint.inspect}") if debug > 1
		return fprint
	end

	def do_setvars(name)
	# Used to tell the password guesser what to try and where and what it looks like when its good
	# / as a path and 200 as a success are assumed (so for basic auth, just give users and it will try them)
	#   fprint is the struct returned by fingerprint()

	#   when setting urls to try, if the username/password are passed in the URL or as data (either post or get), use 
	#		_^_USER_^_ as a placeholder for the username
	#		_^_PASS_^_ as a placeholder for the password
	#   they will be substituted later for each username/password
	debug = 0
		print_status("SetVars with name #{name}") if debug > 1
		data = Hash.new {}
		datafile = File.join(Msf::Config.install_root, 'data', 'wordlists', 'http_default_settings.csv')
		i = 0
		begin
		fd = CSV.foreach(datafile) do |x|
			next if(x[0] =~ /^\#/)
			print_status("Comparing '#{name}' to '#{x[0]}'") if debug > 2
			next if(x[0] != name)

			if(x.length != 6)
				print_error("WARNING: brute has " << x.length.to_s << " members (" << x.inspect << ")")
			end

			#x0 - name, x1 = users, x2 = urls, x3=success, x4 = opts, x5=try
			print_status("Found entry! #{x.inspect}") if debug > 1
			while(i < x.length)
				if(x[i] != nil)
					x[i].gsub!('\\\\', '\\')
					x[i].gsub!('\x22', '"')
					x[i].gsub!('\x2c', ',')
				end
				i = i + 1
			end
			users = (x[1] == nil) ? nil : x[1].split('\x01')
			urls = (x[2] == nil) ? nil : x[2].split('\x01')
			success = (x[3] == nil) ? nil : x[3].split('\x01')
			opts = (x[4] == nil) ? nil : x[4].split('\x01')
			try = (x[5] == nil) ? nil : x[5].split('\x01')

			print_status("Name Users Urls Success Opts Try | #{name} #{users} #{urls}\n#{success}\n#{opts}\n#{try}") if debug > 1
			if(name == x[0])
				print_good("Match on #{name} (#{users}, #{urls}, #{success}, #{opts}, #{try})") if debug > 0
				if(try != nil and try != '')
					data['try'] = try
					data['urls'] = urls if urls != nil
				else
					data['users'] = users if users != nil
					data['urls'] = urls if urls != nil
					data['success'] = success if success != nil
					data['opts'] = opts if opts != nil
				end	
				print_status("Returning data set to #{data.inspect}") if (debug > 0)	
				return data
			end
		end # foreach
		rescue ::Exception => e
			print_error("Error: '#{e}' '#{e.backtrace}'")
			return data
		end # begin


		case name
			when 'Unknown'
				return data
#		else
#			fprint['Type'] = '' if fprint['Type'] == nil
#			print_error(fprint['vhost'] << " used type " << fprint['Type'] << " and it wasn't recognized...(" << fprint.inspect << ")")
		end

		if(data['urls'] != nil or data['users'] != nil or data['try'] != nil)
			print_status("Leaving do_setvars with data set (#{data.length})...") if debug > 0
			print_status("data: " << data.inspect) if debug > 1
			return data
		else
			print_status("Handler not available for fingerprint: #{name}")
			data['failed'] = true
			return data
		end
	end

	def checkSuccess(res, pieces, success)
	# look at response object and compare to success criteria
		return false if (not res or not success)
			
		debug = 0
		print_status("Check success for #{pieces['raw_path']} #{success.inspect}") if debug > 1
		return false if(success['URL'] == '' and success['CONTENT'] == '' and success['LOCATION'] == '')
		ok = true				# keep going until not ok
		if(pieces == nil) 
			url = '/'
		else
			url = pieces['raw_path']
		end
		success.each do |k,v|
			break if not ok
			print_status("Checking #{k} #{v} at #{url}") if debug > 2
			chop k if(k =~ /.\w+\d$/)
			if(k == "CODE") 
				print_status("Comparing #{res.code} to #{v}") if debug > 2
				if( (300..309).include?(res.code.to_i) or (400..510).include?(res.code.to_i)  )
					ok = false
				elsif(res.code.to_i != 200)
					print_status("#{ip} WARNING: Unexpected server response...(#{code})")
				end
			elsif(k == "URL")
				print_status("Comparing " + url + " to " + v) if debug > 2
				if(v != url or res.code != 200)
					ok = false
				elsif( not ((300..309).include?(res.code) or (400..510).include?(res.code)) )
					print_status("#{ip} WARNING: Unexpected server response...(#{code})")
				end
			elsif(k == "LOCATION")
				print_status("Comparing " << res.headers['Location'] << " to " + v) if debug > 2
				if(v != res.headers['Location'])
					ok = false
				else
					print_status("Res: " << res.inspect) if debug > 2
				end
			elsif(k == "Location")
				print_status("Result: " << res.inspect)
				if not res.headers.has_key?('Location')
					ok = false
					break
				end
				print_status("Comparing " << res.headers['Location'] << " to Regexp:" + v) if debug > 2
				op, r, i, str = v.split('\x00',4)
				i = (i) ? true : false
				print_status("Comparing " << res.headers['Location'] << " to #{v} with op #{op} r #{r} i #{i} str #{str}") if debug > 2
				if(r == "m")
					print_status("Doing pattern matching...") if debug > 2
					ok = (res.headers['Location'].scan(Regexp.new("#{str}", i)).length > 0)
				else
					print_status("Doing equals...") if debug > 2
					# direct match instead of regexp
					ok = res.headers['Location'] == str
				end

				if(op == '!')
					ok = !ok
				end
			 else # matches CONTENTx
				next if v == nil
				print_status("Comparing content (#{res.body}) to #{v}") if debug > 2
				if(res.body == nil or res.body.to_s == "" )
					print_status("Didn't get any content back...FAIL?") if debug > 1
					ok = false
				elsif(debug > 2)
					print_status("REPLY: #{res.body} (" + res.body.to_s + ")")
				end
				op, r, i, str = v.split('\x00',4)
#							op = tmp[0]; r=tmp[1]; i=tmp[2]; str=tmp[3]
				i = (i == 'true') ? true : false
				print_status("Comparing content to #{v} with op #{op} r #{r} i #{i} str #{str}") if debug > 2
				if(r == "m")
					ok = (res.body.scan(Regexp.new("#{str}", i)).length > 0)
					print_status("Doing pattern matching on content...ok: #{ok} (" << ok.inspect << ")") if debug > 2
				else
					print_status("Doing equals...") if debug > 2
					# direct match instead of regexp
					ok = (res.body == str)
				end

				if(op == '!')
					ok = !ok
				end
			end
		end # success.each
		return ok
	end


	def do_report(fprint, pieces)
		return if fprint == nil
		if(framework.db.inspect !~ /database active\)\>\,/)
#			print_error("WARNING: Database connection not active, result not stored.")
		end
	#	print_status("Self: #{framework.db.framework}")
		proto = pieces['proto']

		if(pieces.has_key?('ip') )
			ip = pieces['ip']
		else

			ip = pieces['vhost']
			if(ip !~ /^\d+\./)
				print_error("IP is not an IP #{ip}, pieces: #{pieces.inspect}, finger: #{fprint.inspect}")
			end
		end

		port = pieces['port'].to_i
		url = "#{proto}://#{ip}"
		if( (proto == 'https' and port == 443) or (proto == 'http' and port == 80) )
			url << "#{pieces['raw_path']} "
		else
			url << ":#{port}#{pieces['raw_path']} "
		end

		info = "URL: #{url}"
		out = "#{ip}, "
		out << "#{fprint['Name']}, #{fprint['Type']}, #{fprint['SubType']}, "
		if(fprint.has_key?('Manufacturer') )
			out << "#{fprint['Manufacturer']}, "
		end
		out << "#{url} "
		if(fprint['Title'] != '') 
			out << "(#{fprint['Title']})"
		end

		out.gsub!('/\s+/', ' ')

		info << "\nName: #{fprint['Name']}"
		info << "\nType: #{fprint['Type']}"
		info << "\nSubType: #{fprint['SubType']}"
		info << "\nVariant: #{fprint['Variant']}"
		info << "\nServer: #{fprint['Server']}"
		info << "\nTitle: #{fprint['Title']}"

		report_service(
			:host	=> ip,
			:port	=> port,
			:proto	=> proto,
			:name	=> 'http_fingerprint',
			:info	=> info
			)
		print_status(out)

		rescue ::ActiveRecord::StatementInvalid
	end

	def do_report2(pieces, account)
	debug = 0
		if(framework.db.inspect !~ /database active\)\>\,/)
#			print_error("WARNING: Database connection not active, result not stored.")
		end

		print_status("Pieces: #{pieces.inspect}\nAccount: #{account.inspect}") if debug > 2

		proto = pieces['proto']
		ip = pieces['vhost']
		port = pieces['port'].to_i
		url = "#{proto}://#{ip}"
		if( (proto == 'https' and port == 443) or (proto == 'http' and port == 80) )
			url << "#{pieces['raw_path']} "
		else
			url << ":#{port}#{pieces['raw_path']} "
		end

		out = "#{ip}, "
		if(pieces['Name'] != '')
			out << "#{pieces['Name']}, "
		end

		if(pieces.has_key?('try') )
			if(pieces['try'])
				pieces['try_str'].chomp!(' ')
				pieces['try_str'].gsub!(' ', ' or ')
				out << "Try: #{pieces['try_str']} for "
			end
		else

			if(not account.has_key?('failed') )
				if(account['user'] == '' && account['pass'] == '')
					out << "( password not set ), "
				else
					account['user'] = 'unset' if(account['user'] == '')
					out << "('#{account['user']}'/"
					account['pass'] = 'unset' if(account['pass'] == '')
					out << "'#{account['pass']}'), "
				end
			end
		end

		out << "#{url}"

#		report_service(
#			:host	=> ip,
#			:port	=> port,
#			:proto	=> proto,
#			:name	=> 'http_fingerprint',
#			:info	=> info
#			)
		if( (account.has_key?('failed') or pieces.has_key?('try')) and datastore['VERBOSE'] )
			print_status(out)
		elsif(not account.has_key?('failed') )
			print_good(out)
		end
	end


	def run_host(ip)
	debug = 0
		path = '/'
		proto = (datastore['RPORT'] == '443') ? 'https' : 'http'
		datastore['SSL'] = true if(proto == 'https' and not datastore['SSL'] ) 

		request = {'proto' => proto, 'ip' => ip, 'vhost' => ip, 'port' => datastore['RPORT'], 'raw_path' => '/'}
		request_str = "#{proto}://#{ip}:#{datastore['RPORT']}/"

		response = getURL(request_str, request)
		return if response == nil

		redirect = detectRedirect(response, request)
		redirect['ip'] = ip
		if(redirect['redirect'])
			response, redirect = doRedirect(redirect)
		end
		print_status("Redirect: #{redirect.inspect}") if debug > 0
		fp = fingerprint(response, redirect)

		if(fp != nil)
			do_report(fp, redirect)	
		end

		if( datastore['LOGIN'] and fp != nil) 
			data = Hash.new
			data = do_setvars("#{fp['Name']} #{fp['Variant']}")

			print_status("Checking for properly set usernames/passwords or certain specific error conditions...") if debug > 1

			if(data.size == 0 or data.has_key?('try'))
				print_status("No handler...stopping 1") if debug > 0
				proto = (datastore['RPORT'] == '443') ? 'https' : 'http'
				pieces = Hash['vhost' => ip, 'raw_path' => '/', 'port' => datastore['RPORT'], 'proto' => proto, 'Name' => fp['Name']]
				account = Hash['user' => '', 'pass' => '']
				if(data.has_key?('try') )
					u = ''
					p = ''
					data['try'].each do |x|
						y,z = x.split('\x00')
						u << "'#{y}'/'#{z}' "
					end
					pieces['try'] = true
					pieces['try_str'] = u
				else
					account['failed'] = true
				end
				do_report2(pieces, account)
				return
			end

			urls = (data.has_key?('urls') ) ? data['urls']  : ["/"]
			users = (data.has_key?('users')) ? data['users'] :  ['\x00']

			urls = ['/'] if(urls == nil) 
			users = ['\x00'] if (users == nil)
		
			success_raw =  (data.has_key?('success')) ? data['success'] : nil
			opts_raw = (data.has_key?('opts')) ? data['opts'] : nil

			print_status("Users to checK: " << users.inspect) if debug > 2
			print_status("Success to check: " << success_raw.inspect) if debug > 2
			print_status("Urls to check: " << urls.inspect) if debug > 2
			print_status("Options: " << opts_raw.inspect) if debug > 2

			success = Hash.new
			options = Hash.new
			opts = Hash.new

			# set up defaults for success and opts
			if( success_raw == nil )
				success['CODE'] = 200
			else
			# if have success conditions to check for
				success_raw.each do |x|
					t = x.split('\x02')
					success[t[0]] = t[1]
				end
				success['CODE'] = 200 if(not success.has_key?('CODE') )  
			end

			if(opts_raw != nil)
				opts_raw.each do |x|
					t = x.split('\x02')
					options[t[0]] = t[1]
				end
			end

			if( options != nil )
				options['proto'] = 'http'
				options['proto'] = 'https' if(options['SSL'] == 1)
				if(not options.has_key?('Method') )
					options['Method'] = "GET"
				end
				opts['ctype'] = options.has_key?('Content-Type') ? options['Content-Type'] : nil
				opts['raw_headers'] = ''
				if(options.has_key?('Referer') )
					opts['raw_headers'] << "Referer: #{options['Referer']}\r\n"
				else
					opts['raw_headers'] << "Referer: #{options['proto']}://#{ip}:#{datastore['RPORT']}#{urls[0]}\r\n"
				end

				if ( options.has_key?('Keep-Alive') )
					opts['raw_headers'] << "Connection: keep-alive\r\nKeep-Alive: 300\r\n" 
				end

				if ( options.has_key?('cookie') )
					opts['cookie'] = options['cookie']	
				end

				print_status("Ended up with headers of " << opts['raw_headers'].to_s) if debug > 1
			end

			if(datastore['RPORT'] == '443' or options['SSL'] == 1)
				print_status("Detected need to change to SSL...") if debug > 1
				datastore['SSL'] = true
				opts['ssl'] = true
				options['proto'] = 'https'

			end

			print_status("Checking URLS...(" << urls.inspect << ")") if debug > 0
			response = nil
			redirect = Hash.new
			ok = false
			auth_orig = ''
			while( url = urls.shift)
			# urls & users set by fingerprint(), for each URL try the given users
			# most of the time $@urls = 1; however, I did lump some together, so there are occasionally more than one
				break if ok
				print_status("URL: #{url}") if debug > 2

				users.each do |auth_token| 
					print_status("Checking auth_token '" << auth_token.inspect << "'") if debug > 2
					user = ''
					password = ''
					if(auth_token != '\x00')
						user, password = auth_token.split(/\\x00/,2)
					end
					print_status("doing user/pass (#{auth_token}): '#{user.inspect}' / '#{password.inspect}'") if debug > 2			

					response = nil
					if(user != '' and password != '' and not options.has_key?('AUTHTYPE') )
						options['AUTHTYPE'] = nil
					end

					if(options['AUTHTYPE'] == 'BASIC')
						print_status("User '#{user}' / Pass '#{password}' encoded is " << Rex::Text.encode_base64("#{user}:#{password}")) if debug > 2
						opts['raw_headers'] << "Authorization: Basic " << Rex::Text.encode_base64("#{user}:#{password}") << "\r\n"
					elsif(not options['Method'] == 'POST' and options['AUTHTYPE'] != nil)
						print_error("Unsupported authorization type of #{options['AUTHTYPE']}")
						return
					end

					if(options.has_key?('Args') )
						if(auth_orig == '' )
							print_status("Setting up origargs to #{options['Args'].inspect}") if debug > 2
							auth_orig.replace(options['Args'])
						else
						# it is set, so this isn't first try, reset it back
							print_status("Reset Args back to original: #{options['OrigArgs'].inspect}") if debug > 2
							options['Args'].replace(auth_orig)
						end
						print_status("Trying to substitute user '#{user}' / pass '#{password}'") if debug > 2
						if(options.has_key?('SubType') )
							if(options['SubType'] == 'Base64')
								u = Rex::Text.encode_base64(user)
								u.gsub!(/\=/, '%3d')
								options['Args'].sub!(/_\^_USER_\^_/, u )
								p = Rex::Text.encode_base64(password)
								p.sub!(/\=/, '%3d')
								options['Args'].gsub!(/_\^_PASS_\^_/, p)
								print_status("urlargs changed to #{options['Args']}...") if debug > 2
							end
						else

							options['Args'].sub!(/_\^_USER_\^_/, user)
							options['Args'].sub!(/_\^_PASS_\^_/, password)
							print_status("urlargs changed to #{options['Args']}...") if debug > 2
						end
					end	
					request = "#{options['proto']}://#{ip}:#{datastore['RPORT']}#{url}"

					if(options['Method'] == "GET")
						opts['uri'] = url
						opts['uri'] = "#{opts['uri']}?#{options['Args']}" if options['Args'] 
					else
						opts['method'] = options['Method']
						opts['data'] = options['Args'] if options['Args']
					end
					opts['vhost'] = ip
					print_status("Opts: #{opts.inspect}") if debug > 2
					print_status("Sending request for #{request} using #{options['Method']} passing #{options['Args']} (#{user} / #{password})...\nopts: #{opts.inspect}\nSSL:#{options['ssl']}") if debug > 0

					response = getURL(request, pieces, opts)
					tmp_cookie = cookie(response)
					opts['cookie'] = tmp_cookie if tmp_cookie != nil
					next if(response == nil)
					print_status("Response: " << response.inspect << "\nLooking for " << success.inspect) if debug > 1		

					# check redirections
					req = "GET #{url} HTTP/1.1\r\nHost: #{ip}\r\n\r\n"
					path = "#{url}"
					print_status("Checking redirects for code #{success['CODE']}...") if debug > 1
					redirect = detectRedirect(response, request)
					print_status("Redirect set to #{redirect.inspect}") if debug > 2
					if(success['CODE'] != 200)
						if(redirect['redirect'])
							response, redirect = doRedirect(redirect)
							next if(response == nil)
						end
					end
					# don't redirect if CODE not 200 for success as you lose what you were looking for
					print_status("Response after redirect: " << response.inspect << "\nPath #{redirect.inspect}") if debug > 1		

					print_status("Checking success criterion...") if debug > 2
					ok = checkSuccess(response, redirect, success)
					if ok
						account = Hash['user' => user, 'pass' => password]
						redirect['Name'] = "#{fp['Name']} #{fp['Variant']}"
						do_report2(redirect, account)
						break
					end

					break if(response.code == 404) # print_status("Skipping URL #{path} because server says it doesn't exist")
				end # users.each
			
				if(response == nil)
					print_error("#{ip} failed to respond to requests...") if debug > 0
					break
				elsif(response.code == 401 and ok == false and urls.length > 0)
				# 401 means page was there, auth just failed, no sense in trying the other URLs
					print_status("401 code, page found, user's didn't work...stopping...") if debug > 2
					break
				end
			end #while url
			if(not ok and response != nil)
				account = Hash['failed' => true]
				redirect['Name'] = "#{fp['Name']} #{fp['Variant']}"
				redirect['raw_path'] = '/'
				do_report2(redirect, account)
			end

		end



		rescue Rex::ConnectionError
			# stay silent for down hosts
		rescue Timeout::Error
		rescue ::Exception => e
			print_error("Error: '#{ip}' '#{e.class}' '#{e}' '#{e.backtrace}'")
	end # end run host
end
