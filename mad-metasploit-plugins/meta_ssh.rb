#
# $Id$
# $Revision$
#

# top level constant ?!

ARCH_SSH = "ssh" #Tried as class variable without success

module Msf

###
#
# MetaSSH by alhazred
# Dispatcher additions by rageltman
#
###

class Plugin::MetaSSH < Msf::Plugin


  #attr_accessor :framework

	class MetaSSHCommandDispatcher
	  include Msf::Ui::Console::CommandDispatcher

	  # Displatcher name
		def name
		  "metaSSH"
		end

		#Command list
		def commands
			{
				"ssh_open"					=> "Open MetaSSH session"
			}
		end

		#Our commands
		def cmd_ssh_open_help
			print_line("Usage: ssh_open [options] [hosts]")
			print_line
			print_line("OPTIONS:")
			print_line("    -l        Login Username")
			print_line("    -c        Credential, file or pass")
			print_line("    -f        File containing hosts (from -R output for instance)")
			print_line("    -h        Help Banner")
		end

		def cmd_ssh_open( *args )

			opts = Rex::Parser::Arguments.new(
				"-l" => [ true, "Login"],
				"-c" => [ true, "Credentials (passwd or keyfile)"],
				"-h" => [ false, "Command help"],
				"-f" => [ false, "File containing hosts"]
			)
			#Parse the opts
			ips = []
			login = ''
			cred = nil
			hosts_file = ''

			opts.parse(args) do |opt, idx, val|
      	case opt
     		when '-h'
     			cmd_ssh_open_help
     			return
     		when '-l'
     			login = val
	 			when '-c'
 					cred = val
				when '-f'
					hosts_file = val
				else
					#guess it must be an address
					ips << val
				end
			end

			#Parse hosts file if exists
			File.read(hosts_file).each_line do |ip|
				ips << ip
			end if File.file?(hosts_file)


			#Configure our module
			if File.file?(File.expand_path(cred))
				mod = framework.modules.create('exploit/multi/ssh/login_pubkey')
				mod.datastore['KEY_FILE'] = cred
			else
				mod = framework.modules.create('exploit/multi/ssh/login_password')
				mod.datastore['PASS'] = cred
			end
			mod.datastore['USER'] = login

			#Build our range walker
			targets = Rex::Socket::RangeWalker.new(ips)

			#Run against each IP in the rangewalker
			targets.each do |ip|
				print_good("Running #{mod.refname} against #{ip}")
				mod.datastore['RHOST'] = ip
				mod.exploit_simple(
					'Payload' => 'ssh/metassh_session',
					'Target'  => mod.datastore['TARGET']
				)
			end
		end
  end #end dispatcher

  def initialize( framework, opts )
  	super

		# register our new arch type

		::ARCH_TYPES << ::ARCH_SSH unless ::ARCH_TYPES.include?(::ARCH_SSH)

		# add meta_ssh lib to the path

		$:.unshift(File.join(File.dirname(__FILE__),"meta_ssh","lib"))

		# load our modules

		framework.modules.add_module_path(File.join(File.dirname(__FILE__),"meta_ssh","modules")).each do |m|
			print_good("Added #{m.last} #{m.first.capitalize} modules for metaSSH")
		end

		# load the dispatcher

		add_console_dispatcher( MetaSSHCommandDispatcher )
  end

  def cleanup
	  remove_console_dispatcher( 'metaSSH' )
	  $:.delete_if {|e| e =~ /meta_ssh\/lib/}
	  framework.modules.remove_module_path(File.join(File.dirname(__FILE__),"meta_ssh","modules"))
  end

  def name
  	"metaSSH"
	end


end

end

