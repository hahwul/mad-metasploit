#!/usr/bin/env ruby

require 'thread'
require 'rex/post/meta_ssh/channel'
require 'rex/io/stream'
require 'rex/socket/tcp'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/forward_mixin'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/socket_after_close'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/socket_after_accept'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Net
module SocketSubsystem

###
#
# This class represents a logical TCP client connection
# that is established from the remote machine and tunnelled
# through the established ssh connection
#
###
class TcpClientChannel 
  include Rex::IO::Stream 
	attr_accessor :lsock
  attr_accessor :client
  

  def fd
    lsock.fd
  end

  ##
	#
	# Factory
	#
	##

	#
	# Opens a TCP client channel using the supplied parameters.
	#
	def TcpClientChannel.open(client, params)
      
		lsock   = nil
		rsock   = nil
		laddr   = '127.0.0.1'
		lport   = 0
		threads = []
    c=TcpClientChannel.new(client)
		mutex   = ::Mutex.new

		threads << Rex::ThreadFactory.spawn('MetaSSHTcpSocketPair', false) {
			server = nil
			mutex.synchronize {
				threads << Rex::ThreadFactory.spawn('MetaSSHTcpSocketPairClient', false) {
					mutex.synchronize {
						c.lsock = Rex::Socket.create_tcp('PeerHost' => laddr, 'PeerPort' => lport)
          }
				}
          unless client.ssh.forward.respond_to?(:local_forwarded_ports)
            client.ssh.forward.extend(ForwardMixin)
          end

          server=client.ssh.forward.local(0, params.peerhost, params.peerport)
				  if (server.getsockname =~ /127\.0\.0\.1:/)
					  # JRuby ridiculousness
					  caddr, lport = server.getsockname.split(":")
					  caddr = caddr[1,caddr.length]
					  lport = lport.to_i
				  else
					  # Sane implementations where Socket#getsockname returns a
					  # sockaddr
					  lport, caddr = ::Socket.unpack_sockaddr_in( server.getsockname )
				  end
         
          # clean up after ourselves, remove the forwarding when the socket closes
          server.extend(SocketAfterAccept)
          server.after_accept do |listener,socket| 
            socket.extend(SocketAfterClose)
            socket.after_close do |s| 
              #client.ssh.forward.cancel_local(l_port,l_addr)
            end
          end
			}
		}

		threads.each { |t| t.join }
    return c
	end

	##
	#
	# Constructor
	#
	##

	#
	# Passes the channel initialization information up to the base class.
	#
	def initialize(client)
    self.client=client

	end

	#
	# Closes the write half of the connection.
	#
	def close_write
		return shutdown(1)
	end

	#
	# Shutdown the connection
	#
	# 0 -> future reads
	# 1 -> future sends
	# 2 -> both
	#
	def shutdown(how = 1)
    lsock.shutdown(how)
		return true
	end

  def close()
    lsock.close
  end

	#
	# Wrap the _write() call in order to catch some common, but harmless Windows exceptions
	#
	def syswrite(args)
	  lsock.write(*args)
  end

  def sysread(length)
    lsock.read(length)
  end



		def type?
			'tcp'
		end

		def getsockname
			# Find the first host in our chain (our address)
			hops = 0
			csock = lsock
			tmp,caddr,cport = csock.getsockname
			tmp,raddr,rport = csock.getpeername
			maddr,mport = [ channel.params.localhost, channel.params.localport ]
			[ tmp, "#{caddr}#{(hops > 0) ? "-_#{hops}_" : ""}-#{raddr}", "#{mport}" ]
		end

		def getpeername
			return super if not channel
			tmp,caddr,cport = channel.client.sock.getpeername
			maddr,mport = [ channel.params.peerhost, channel.params.peerport ]
			[ tmp, "#{maddr}", "#{mport}" ]
		end

end

end; end; end; end; end; end; end

