##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'HP LaserJet Printer Scanner',
			'Description'    => %q{
				Look for HP LaserJet printers on the network and try to connect to them via
				Printer Job Language (PJL) detecting basic informations such as ID and S/N.
			},
			'References'     =>
				[
					['CVE', '2010-4107'],
					['URL', 'http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf'],
					['EDB', '15631'],
					['URL', 'http://packetstormsecurity.org/files/103778/hpjetdirect-exec.rb.txt'],
				],
			'Author'         => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(9100),
				OptInt.new('TIMEOUT', [true, 'Timeout for the printer probe', 5])
			], self.class)

		deregister_options('VHOST')
	end

	def to
		return 5 if datastore['TIMEOUT'].to_i.zero?
		datastore['TIMEOUT'].to_i
	end

	def run_host(ip)

		# PJL commands are recognized by the following HP printers:
		#
		# . LaserJet IIISi, 4Si, 4SiMx, 5Si, 5SiMx, 5Si Mopier
		# . LaserJet 1100 Series, 2100 Series
		# . LaserJet 4000 Series, 5000 Series
		# . LaserJet 8000 Series, 8100 Series
		# . LaserJet 4V, 4MV
		# . LaserJet 4, 4 Plus, 4M, 4M Plus, 5, 5M
		# . LaserJet 4L, 4ML, 4LJ Pro, 4LC, 5L, 6L
		# . LaserJet 4P, 4MP, 4PJ, 5P, 6P, 6MP
		# . Color LaserJet, Color LaserJet 5, 5M
		# . Color LaserJet 4500 Series, 8500 Series
		# . DeskJet 1200C, 1600C
		# . DesignJet Family
		# . PaintJet XL300

		port = datastore['RPORT'].to_i
		info_command = ["INFO ID","INFO CONFIG","INFO PAGECOUNT","INFO STATUS"]

		# Format of PJL Commands - #4
		#
		# @PJL command [command modifier : value] [option name [= value]] [<CR>]<LF>
		# This format is used for all of the other PJL commands.
		# The PJL prefix .@PJL. always must be uppercase.
		prefix = "@PJL "
		postfix = "\r\n"

		found = Hash.new()

		::Timeout.timeout(to) do

			begin
				vprint_status("Connecting to #{ip}:#{port}...")

				s = connect

				info_command.each do |command|

					req = prefix + command + postfix

					s.put(req)
					res = s.get(-1,1)

					# I don't care the ERROR shown on the DISPLAY!
					if not res
						raise RuntimeError, "#{ip}:#{port} error in receiving data."
					elsif res and res.to_s =~ /ERROR/ and res.to_s !~ /DISPLAY/
						raise RuntimeError, "#{ip}:#{port} bad command or error!"
					end

					resx = res.to_s[res.index(postfix),res.length]

					if command =~ /INFO ID/

						found[ip] = Hash.new()

						found[ip]['port'] = port

						if resx =~ /^"(.*)"/
							report_service(
								:host => ip,
								:port => port,
								:name => "HP LaserJet printer",
								:info => $1.chop
							)

							found[ip]['model'] = $1.chop
						else
							resx.gsub!(/^\s+|\s+$|\n+|\r+/,'')

							report_service(
								:host => ip,
								:port => port,
								:name => "HP LaserJet printer",
								:info => resx
							)

							found[ip]['model'] = resx
						end
					end

					if command =~ /^INFO PAGECOUNT/
						resx.gsub!(/^\s+|\s+$|\n+|\r+/,'')
						found[ip]['pages'] = resx
					end

					if command =~ /^INFO STATUS/
						if resx =~ /^DISPLAY="(.*)"/
							found[ip]['display1'] = $1
						end
						if resx =~ /^DISPLAY2="(.*)"/
							found[ip]['display2'] = $1
						end
					end

					if resx =~ /^SERIAL NUMBER="(.*)"/
						found[ip]['serial'] = $1
					end

					if resx =~ /^FORMATTER NUMBER="(.*)"/
						found[ip]['formatter'] = $1
					end

					if resx =~ /^FIRMWARE DATECODE=(.*)/
						found[ip]['firmware'] = $1
					end

				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
			ensure
				disconnect
			end
		end

		found.each do |k, v|

			#print_good("IP address        : #{k}")
			#print_good("Port              : #{v['port']}")
			#print_good("Model id          : #{v['model']}")
			#print_good("Pages count       : #{v['pages']}")
			#print_good("Display 1         : #{v['display1']}")
			#print_good("Display 2         : #{v['display2']}")
			#print_good("Serial number     : #{v['serial']}")
			#print_good("Formatter number  : #{v['formatter']}")
			#print_good("Firmware datecode : #{v['firmware']}")
			#print_line('')

			# This... to avoid the overlap of the output :(
			print_good("IP address        : #{k}\n    Port              : #{v['port']}\n    Model id          : #{v['model']}\n    Pages count       : #{v['pages']}\n    Display 1         : #{v['display1']}\n    Display 2         : #{v['display2']}\n    Serial number     : #{v['serial']}\n    Formatter number  : #{v['formatter']}\n    Firmware datecode : #{v['firmware']}\n")

			report_service(
				:host  => k,
				:port  => v['port'],
				:proto => 'tcp',
				:name  => v['model'],
				:info  => "firmware:#{v['firmware']}"
			)
		end
	end
end

=begin
This module needs a better way to output instead
=end
