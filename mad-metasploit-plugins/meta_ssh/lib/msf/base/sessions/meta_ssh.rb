##
# $Id$
##

require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'rex/post/meta_ssh'
module Msf
module Sessions

###
#
# This class represents a session compatible interface to an ssh connection
#
###
class MetaSSH < Rex::Post::MetaSSH::Client 

	#
	# The meterpreter session is interactive
	#
	include Msf::Session
	include Msf::Session::Interactive
	include Msf::Session::Comm
	#
	# This interface supports interacting with a single command shell.
	#
	include Msf::Session::Provider::SingleCommandShell

	include Msf::Session::Scriptable

	# Override for server implementations that can't do ssl
	def supports_ssl?
	  false
	end
	def supports_zlib?
		false
	end

	#
	# Initializes a meterpreter session instance using the supplied rstream
	# that is to be used as the client's connection to the server.
	#
	def initialize(ssh, opts={})
    super(nil,opts)
		init_ssh(ssh,opts)
    self.console = Rex::Post::MetaSSH::Ui::Console.new(self)
	end

	#
	# Returns the session type as being 'metaSSH'.
	#
	def self.type
		"metaSSH"
	end

	#
	# Calls the class method
	#
	def type
		self.class.type
	end

	def shell_init
		return true if @shell

		cmd_exec="/bin/sh -i"
		@shell = Channel.new(self) {|c| c.channel.exec(cmd_exec)}
    @shell.type="exec"
    @shell.info="cmd_exec"
    return @shell
	end

	#
	# Read from the command shell.
	#
	def shell_read(length=nil, timeout=1)
		shell_init

		length = nil if length < 0
		begin
			rv = nil
			# Meterpreter doesn't offer a way to timeout on the victim side, so
			# we have to do it here.  I'm concerned that this will cause loss
			# of data.
			Timeout.timeout(timeout) {
				rv = @shell.channel.read(length)
			}
			framework.events.on_session_output(self, rv) if rv
			return rv
		rescue ::Timeout::Error
			return nil
		rescue ::Exception => e
			shell_close
			raise e
		end
	end

	#
	# Write to the command shell.
	#
	def shell_write(buf)
		shell_init

		begin
			framework.events.on_session_command(self, buf.strip)
			len = @shell.channel.write("#{buf}\n")
		rescue ::Exception => e
			shell_close
			raise e
		end

		len
	end

	def shell_close
		@shell.close
		@shell = nil
	end

	def shell_command(cmd)
		# Send the shell channel's stdin.
		shell_write(cmd + "\n")

		timeout = 5
		etime = ::Time.now.to_f + timeout
		buff = ""

		# Keep reading data until no more data is available or the timeout is
		# reached.
		while (::Time.now.to_f < etime)
			res = shell_read(-1, timeout)
			break unless res
			timeout = etime - ::Time.now.to_f
			buff << res
		end

		buff
	end
	##
	#
	# Msf::Session overrides
	#
	##

	#
	# Cleans up the metaSSH client session.
	#
	def cleanup
		cleanup_ssh

	end

	#
	# Returns the session description.
	#
	def desc
		"metaSSH"
	end


	##
	#
	# Msf::Session::Scriptable implementors
	#
	##

	#
	# Runs the metaSSH script in the context of a script container
	#
	def execute_file(full_path, args)
		o = Rex::Script::MetaSSH.new(self, full_path)
		o.run(args)
	end


	##
	#
	# Msf::Session::Interactive implementors
	#
	##

	#
	# Initializes the console's I/O handles.
	#
	def init_ui(input, output)
		self.user_input = input
		self.user_output = output
		console.init_ui(input, output)
		console.set_log_source(log_source)

		super
	end

	#
	# Resets the console's I/O handles.
	#
	def reset_ui
		console.unset_log_source
		console.reset_ui
	end

	#
	# Terminates the session
	#
	def kill
		begin
			cleanup_ssh
			self.sock.close
		rescue ::Exception
		end
		framework.sessions.deregister(self)
	end

	#
	# Run the supplied command as if it came from suer input.
	#
	def queue_cmd(cmd)
		console.queue_cmd(cmd)
	end

	#
	# Explicitly runs a command in the meterpreter console.
	#
	def run_cmd(cmd)
		console.run_single(cmd)
	end

  #
  # get the tunnel peer
  #

  def tunnel_peer
    
    sock=self.ssh.transport.socket
    misc, host, port= sock.getpeername
    return "#{host}:#{port}"
  end

	#
	# Populate the session information.
	#
	# Also reports a session_fingerprint note for host os normalization.
	#
	def load_session_info()
		begin
			::Timeout.timeout(60) do
			  
         #nothing
        
      end
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			# Log the error but otherwise ignore it so we don't kill the
			# session if reporting failed for some reason
			elog("Error loading sysinfo: #{e.class}: #{e}")
			dlog("Call stack:\n#{e.backtrace.join("\n")}")
		end
	end

	#
	# Interacts with the meterpreter client at a user interface level.
	#
	def _interact
		framework.events.on_session_interact(self)
		# Call the console interaction subsystem of the meterpreter client and
		# pass it a block that returns whether or not we should still be
		# interacting.  This will allow the shell to abort if interaction is
		# canceled.
		console.interact { self.interacting != true }

		# If the stop flag has been set, then that means the user exited.  Raise
		# the EOFError so we can drop this bitch like a bad habit.
		raise EOFError if (console.stopped? == true)
	end


	##
	#
	# Msf::Session::Comm implementors
	#
	##

	#
	# Creates a connection based on the supplied parameters and returns it to
	# the caller.  The connection is created relative to the remote machine on
	# which the meterpreter server instance is running.
	#
	def create(param)
		sock = nil

		# Notify handlers before we create the socket
		notify_before_socket_create(self, param)

		sock = net.socket.create(param)

		# sf: unsure if we should raise an exception or just return nil. returning nil for now.
		#if( sock == nil )
		#  raise Rex::UnsupportedProtocol.new(param.proto), caller
		#end

		# Notify now that we've created the socket
		notify_socket_created(self, sock, param)

		# Return the socket to the caller
		sock
	end

	attr_accessor :console # :nodoc:
	attr_accessor :target_id


	attr_accessor :rstream # :nodoc:

end

end
end

