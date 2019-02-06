
module Rex
module Post
module MetaSSH
module Ui

###
#
# The system level portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Sys

	Klass = Console::CommandDispatcher::Stdapi::Sys

	include Console::CommandDispatcher

	#
	# Options used by the 'execute' command.
	#
	@@execute_opts = Rex::Parser::Arguments.new(
		"-a" => [ true,  "The arguments to pass to the command."                   ],
		"-c" => [ false, "Channelized I/O (required for interaction)."             ],
		"-f" => [ true,  "The executable command to run."                          ],
		"-h" => [ false, "Help menu."                                              ],
		"-i" => [ false, "Interact with the process after creating it."            ])

	#
	# List of supported commands.
	#
	def commands
		{
			"execute"  => "Execute a command",
			"shell"    => "Drop into a system command shell",
		}
	end

	#
	# Name for this dispatcher.
	#
	def name
		"Stdapi: System"
	end

	#
	# Executes a command with some options.
	#
	def cmd_execute(*args)
		if (args.length == 0)
			args.unshift("-h")
		end
    channel     = nil
		session     = nil
		interact    = false
		channelized = nil
		cmd_args    = nil
		cmd_exec    = nil
		use_thread_token = false

		@@execute_opts.parse(args) { |opt, idx, val|
			case opt
				when "-a"
					cmd_args = val
				when "-c"
					channelized = true
				when "-f"
					cmd_exec = val
				when "-H"
					hidden = true
				when "-m"
					from_mem = true
				when "-d"
					dummy_exec = val
				when "-k"
					desktop = true
				when "-h"
					print(
						"Usage: execute -f file [options]\n\n" +
						"Executes a command on the remote machine.\n" +
						@@execute_opts.usage)
					return true
				when "-i"
					channelized = true
					interact = true
				when "-t"
					use_thread_token = true
				when "-s"
					session = val.to_i
			end
		}
	  if(channelized)	
      channel=Channel.new(client) {|c| c.channel.exec(cmd_exec)}
      channel.type="exec"
      channel.info=cmd_exec
      print_line("Channel #{channel.cid} created.") if channel
    else
      print_line(client.sys.exec(cmd_exec,cmd_args))
    end
		if (interact and channel)
			shell.interact_with_channel(channel)
		end
	end


	#
	# Drop into a system shell as specified by %COMSPEC% or
	# as appropriate for the host.
	def cmd_shell(*args)
			path = "/bin/bash -i"
			cmd_execute("-f", path, "-c", "-i")
	end

end

end
end
end
end

