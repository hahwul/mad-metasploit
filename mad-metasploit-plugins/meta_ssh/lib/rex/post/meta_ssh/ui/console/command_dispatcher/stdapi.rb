require 'rex/post/meta_ssh'

module Rex
module Post
module MetaSSH
module Ui

###
#
# Standard API extension.
#
###
class Console::CommandDispatcher::Stdapi

	require 'rex/post/meta_ssh/ui/console/command_dispatcher/stdapi/sys'
  require 'rex/post/meta_ssh/ui/console/command_dispatcher/stdapi/net'
  require 'rex/post/meta_ssh/ui/console/command_dispatcher/stdapi/fs'
	
  Klass = Console::CommandDispatcher::Stdapi

	Dispatchers = 
		[
			Klass::Sys,
      Klass::Net,
      Klass::Fs
		]

	include Console::CommandDispatcher

	#
	# Initializes an instance of the stdapi command interaction.
	#
	def initialize(shell)
		super

		Dispatchers.each { |d|
			shell.enstack_dispatcher(d)
		}
	end

	#
	# List of supported commands.
	#
	def commands
		{
		}
	end

	#
	# Name for this dispatcher
	#
	def name
		"Standard extension"
	end

end

end
end
end
end
