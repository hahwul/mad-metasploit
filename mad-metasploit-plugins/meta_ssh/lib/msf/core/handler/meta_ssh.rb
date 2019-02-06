module Msf
module Handler

###
#
# This handlers the metassh session
#
###
module MetaSSH

	include Msf::Handler

	#
	# Returns the string representation of the handler type,
	#
	def self.handler_type
		return "MetaSSH"
	end

	#
	# Returns the connection oriented general handler type, in this case
	# 'find'.
	#
	def self.general_handler_type
		"MetaSSH"
	end

	#
	# Initializes the find port handler and adds the client port option that is
	# required for port-based findsock payloads to function.
	#
	def initialize(info = {})
		super
	end

	
	def create_session(ssh,opts={})
		# If there is a parent payload, then use that in preference.
			s = Sessions::MetaSSH.new(ssh,opts)
			# Pass along the framework context
			s.framework = framework

			# Associate this system with the original exploit
			# and any relevant information
			s.set_from_exploit(assoc_exploit)

			# If the session is valid, register it with the framework and
			# notify any waiters we may have.
			if (s)
				register_session(s)
			end

			return s
	end

  
  #
	# Check to see if there's a shell on the supplied sock.  This check
	# currently only works for shells.
	#
	def handler(ssh)
			create_session(ssh)
	end

	attr_accessor :_handler_return_value # :nodoc:

end

end
end

