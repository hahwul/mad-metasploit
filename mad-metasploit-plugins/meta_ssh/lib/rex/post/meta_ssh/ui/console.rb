require 'rex/ui'
require 'rex/post/meta_ssh'
require 'rex/logging'

module Rex
module Post
module MetaSSH
module Ui

###
#
# This class provides a shell driven interface to the meterpreter client API.
#
###
class Console

	include Rex::Ui::Text::DispatcherShell

	# Dispatchers
	require 'rex/post/meta_ssh/ui/console/interactive_channel'
	require 'rex/post/meta_ssh/ui/console/command_dispatcher'
	require 'rex/post/meta_ssh/ui/console/command_dispatcher/core'
  require 'rex/post/meta_ssh/ui/console/command_dispatcher/stdapi'
	#
	# Initialize the meterpreter console.
	#
	def initialize(client)
    super("metaSSH")
		# The meterpreter client context
		self.client = client

		# Queued commands array
		self.commands = []

		# Point the input/output handles elsewhere
		reset_ui

		enstack_dispatcher(Console::CommandDispatcher::Core)
    enstack_dispatcher(Console::CommandDispatcher::Stdapi)

		# Set up logging to whatever logsink 'core' is using
		if ! $dispatcher['ssh']
			$dispatcher['ssh'] = $dispatcher['core']
		end
	end

	#
	# Called when someone wants to interact with the ssh client.  It's
	# assumed that init_ui has been called prior.
	#
	def interact(&block)
		init_tab_complete

		# Run queued commands
		commands.delete_if { |ent|
			run_single(ent)
			true
		}

		# Run the interactive loop
		run { |line|
			# Run the command
			run_single(line)

			# If a block was supplied, call it, otherwise return false
			if (block)
				block.call
			else
				false
			end
		}
	end

	#
	# Interacts with the supplied channel.
	#
	def interact_with_channel(channel)
		channel.extend(InteractiveChannel) unless (channel.kind_of?(InteractiveChannel) == true)
		channel.on_command_proc = self.on_command_proc if self.on_command_proc
		channel.on_print_proc   = self.on_print_proc if self.on_print_proc

		channel.interact(input, output)
		channel.reset_ui
	end

	#
	# Queues a command to be run when the interactive loop is entered.
	#
	def queue_cmd(cmd)
		self.commands << cmd
	end

	#
	# Runs the specified command wrapper in something to catch meterpreter
	# exceptions.
	#
	def run_command(dispatcher, method, arguments)
		begin
			super
		rescue Timeout::Error
			log_error("Operation timed out.")
		rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError => e
			log_error("Error running command #{method}: #{e.class} #{e}\n #{e.backtrace.join("\n")}")
      self.client.kill
		rescue  ::Exception => e
			log_error("Error running command #{method}: #{e.class} #{e}\n #{e.backtrace.join("\n")}")
		end
	end

	#
	# Logs that an error occurred and persists the callstack.
	#
	def log_error(msg)
		print_error(msg)

		elog(msg, 'meterpreter')

		dlog("Call stack:\n#{$@.join("\n")}", 'meterpreter')
	end

	attr_reader :client # :nodoc:

protected

	attr_writer :client # :nodoc:
	attr_accessor :commands # :nodoc:

end

end
end
end
end
