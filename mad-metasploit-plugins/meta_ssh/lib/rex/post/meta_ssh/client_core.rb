#!/usr/bin/env ruby

require 'rex/post/meta_ssh/extension'

module Rex
module Post
module MetaSSH

###
#
# This class is responsible for providing the interface to the core
# client-side meterpreter API which facilitates the loading of extensions
# and the interaction with channels.
#
#
###
class ClientCore < Extension

	#
	# Initializes the 'core' portion of the meterpreter client commands.
	#
	def initialize(client)
		super(client, "core")
	end

	##
	#
	# Core commands
	#
	##
	def shutdown
    true
  end

  def use(mod)
    client.add_extension(mod)
  end

end

end; end; end

