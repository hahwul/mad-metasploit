module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Net
module SocketSubsystem


module ForwardMixin

  def local_forwarded_ports
    @local_forwarded_ports
  end



  def remote_forwarded_ports
    @remote_forwarded_ports
  end



    # Starts listening for connections on the local host, and forwards them
    # to the specified remote host/port via the SSH connection. This method
    # accepts either three or four arguments. When four arguments are given,
    # they are:
    #
    # * the local address to bind to
    # * the local port to listen on
    # * the remote host to forward connections to
    # * the port on the remote host to connect to
    #
    # If three arguments are given, it is as if the local bind address is
    # "127.0.0.1", and the rest are applied as above.
    #
    #   ssh.forward.local(1234, "www.capify.org", 80)
    #   ssh.forward.local("0.0.0.0", 1234, "www.capify.org", 80)
    def local(*args)
      if args.length < 3 || args.length > 4
        raise ArgumentError, "expected 3 or 4 parameters, got #{args.length}"
      end

      bind_address = "127.0.0.1"
      bind_address = args.shift if args.first.is_a?(String) && args.first =~ /\D/

      local_port = args.shift.to_i
      remote_host = args.shift
      remote_port = args.shift.to_i

      socket = TCPServer.new(bind_address, local_port)
      lport,caddr=nil,nil

				  if (socket.getsockname =~ /127\.0\.0\.1:/)
					  # JRuby ridiculousness
					  caddr, lport = socket.getsockname.split(":")
					  caddr = caddr[1,caddr.length]
					  lport = lport.to_i
				  else
					  # Sane implementations where Socket#getsockname returns a
					  # sockaddr
					  lport, caddr = ::Socket.unpack_sockaddr_in( socket.getsockname )
				  end

      @local_forwarded_ports[[lport, caddr]] = socket

      session.listen_to(socket) do |server|
        client = server.accept

        debug { "received connection on #{caddr}:#{lport}" }

        channel = session.open_channel("direct-tcpip", :string, remote_host, :long, remote_port, :string, caddr, :long, lport) do |achannel|
          achannel.info { "direct channel established" }
        end
        prepare_client(client, channel, :local)
  
        channel.on_open_failed do |ch, code, description|
          channel.error { "could not establish direct channel: #{description} (#{code})" }
          channel[:socket].close
        end
      end
      socket
    end

end

end; end; end; end; end; end; end;
