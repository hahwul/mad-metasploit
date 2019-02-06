#!/usr/bin/env ruby

require 'thread'
require 'rex/socket'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/tcp_client_channel'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/tcp_server_channel'
require 'rex/logging'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Net

###
#
# This class provides an interface to interacting with sockets
# on the remote machine.  Only support TCP
#
###


class Socket
  attr_accessor :client
	##
	#
	# Constructor
	#
	##

	#
	# Initialize the socket subsystem and start monitoring sockets as they come in.
	#
	def initialize(client)
		self.client = client

		# register the inbound handler for the tcp server channel (allowing us to receive new client connections to a tcp server channel)

	end

	#
	# Deregister the inbound handler for the tcp server channel
	#
	def shutdown
	end

	##
	#
	# Factory
	#
	##

	#
	# Creates an arbitrary client socket channel using the information
	# supplied in the socket parameters instance.  The 'params' argument
	# is expected to be of type Rex::Socket::Parameters.
	#
	def create( params )
		res = nil

		if( params.tcp? )
			if( params.server? )
				res = create_tcp_server_channel( params )
			else
				res = create_tcp_client_channel( params )
			end
		elsif( params.udp? )
			res = create_udp_channel( params )
		end

		return res
	end

	#
	# Create a TCP server channel.
	#
	def create_tcp_server_channel(params)
			return SocketSubsystem::TcpServerChannel.open(client, params)
	end

	#
	# Creates a TCP client channel.
	#
	def create_tcp_client_channel(params)
			channel = SocketSubsystem::TcpClientChannel.open(client, params)
			if( channel != nil )
				return channel.lsock
			end
			return nil
	end

	#
	# Creates a UDP channel.
	#
	def create_udp_channel(params)
		  raise ::Rex::ConnectionError.new("UDP is unsupported for ssh connections")
		end
	end


protected

	attr_accessor :client # :nodoc:

end

end; end; end; end; end; 

