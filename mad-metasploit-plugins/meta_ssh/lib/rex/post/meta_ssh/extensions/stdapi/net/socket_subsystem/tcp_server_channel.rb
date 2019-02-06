require 'timeout'
require 'thread'
require 'rex/socket/parameters'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/tcp_client_channel'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Net
module SocketSubsystem

class TcpServerChannel 

  include Rex::Socket
  include Rex::IO::StreamServer
  attr_accessor :lsock
  attr_accessor :lport
  attr_accessor :params
	attr_accessor :client
  def TcpServerChannel.open(client, params)
    t=TcpServerChannel.new(client)
    lsock=Rex::Socket.create_tcp_server('LocalHost'=>'127.0.0.1', 'LocalPort' => 0)
    lport=lsock.getsockname[2]
    t.client=client
    t.params=params
    t.lsock=lsock
    t.lport=lport
    client.ssh.forward.remote(lport,"127.0.0.1", params.localport, params.localhost)
    return t
  end

  def stop
    # client.ssh.forward.cancel_remote(params.localport, params.localhost)
  end

  alias :close :stop

	#
	# Simply initilize this instance.
	#
	def initialize(client)
	  self.client=client
  end

	#
	# Accept a new tcp client connection form this tcp server channel. This method will block indefinatly
	# if no timeout is specified.
	#
	def accept( opts={} )
		timeout = opts['Timeout'] || -1
		if( timeout == -1 )
			result = lsock.accept
		else
			begin
				::Timeout.timeout( timeout ) {
					result = lsock.accept
				}
			rescue Timeout::Error
				result = nil
			end
		end
		return result
	end

end

end; end; end; end; end; end; end

