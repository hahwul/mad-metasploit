require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/forward_mixin'
module Rex
module Post
module MetaSSH
module Ui

###
#
# The system level portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Net

	Klass = Console::CommandDispatcher::Stdapi::Net

	include Console::CommandDispatcher


	@@portfwd_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help menu."                                              ],
		"-r" => [ true, "remote machine rhost:rport"                              ],
		"-l" => [ true, "local port"                                              ],
    )


  def commands
		{
			"portfwd"  => "forward local port to remote port",
		}
	end

	#
	# Name for this dispatcher.
	#
	def name
		"Stdapi: Net"
	end

	#
	# Executes a command with some options.
	#
	def cmd_portfwd(*args)
		if (args.length == 0)
			args.unshift("-h")
		end
    lport=nil
    rport=nil
    rhost=nil
		@@portfwd_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: portfwd -l localport -r remotehost:remoteport\n\n" +
						"Executes a command on the remote machine.\n" +
						@@portfwd_opts.usage)
					return true
				when "-l"
					lport=val.to_i
				when "-r"
					rhost,rport=val.split(":")
			    rport=rport.to_i
      end
		}
    client.ssh.forward.extend(Rex::Post::MetaSSH::Extensions::Stdapi::Net::SocketSubsystem::ForwardMixin)
    client.ssh.forward.local(lport,rhost,rport)
    true
	end

end

end
end
end
end

