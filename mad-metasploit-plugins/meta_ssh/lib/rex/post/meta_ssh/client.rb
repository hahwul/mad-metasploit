#!/usr/bin/env ruby

require 'socket'
require 'openssl'
require 'rex/post/meta_ssh/channel'
require 'rex/post/meta_ssh/client_core'
require 'rex/post/meta_ssh/object_aliases'
require 'rex/script'
require 'rex/script/meta_ssh'
require 'rex/logging'

module Rex
module Post
module MetaSSH

#
# Just to get it in there...
#
module Extensions
end

###
#
# This class represents a logical metaSSH client class.  This class
# provides an interface that is compatible with the Rex post-exploitation
# interface in terms of the feature set that it attempts to expose.  This
# class is meant to drive a single metaSSH client session.
#
###
class Client
  attr_accessor :ssh, :thread, :channels,:expiration,:send_keepalives,:comm_timeout, :response_timeout
  attr_accessor :tunnel_peer
	#
	# Extension name to class hash.
	#
	@@ext_hash = {}

	#
	# Mutex to synchronize class-wide operations
	#
	@@ssl_mutex = ::Mutex.new

	#
	# Lookup the error that occurred
	#
	def self.lookup_error(code)
		code
	end

	#
	# Checks the extension hash to see if a class has already been associated
	# with the supplied extension name.
	#
	def self.check_ext_hash(name)
		@@ext_hash[name]
	end

	#
	# Stores the name to class association for the supplied extension name.
	#
	def self.set_ext_hash(name, klass)
		@@ext_hash[name] = klass
	end

	#
	# Initializes the ssh context with the supplied ssh instance
	# which communication with the server will be performed.
	#
	def initialize(ssh,opts={})
		init_ssh(ssh, opts)

	end

	#
	# Cleans up the meterpreter instance, terminating the dispatcher thread.
	#
	def cleanup_ssh
    self.fs.sftp.cleanup unless self.fs.nil? or self.fs.sftp.nil?
    ext.aliases.each_value do | extension |
			extension.cleanup if extension.respond_to?( 'cleanup' )
		end
    self.thread.kill
    self.ssh.close

	end


  def add_channel(c)
    c.cid=new_cid
    self.channels[c.cid.to_s]=c
  end

  def remove_channel(c)
    self.channels.delete(c.cid.to_s)
  end

  def find_channel(c)
    return self.channels[c.to_s]
  end

  def new_cid
    @cid_n||=0
    @cid_n=@cid_n+1
    return @cid_n
  end

	#
	# Initializes the ssh client instance
	#
	def init_ssh(ssh,opts={})
    @cid_n=0
    self.ssh         = ssh
    self.channels={}
		self.expiration   = opts[:expiration]
		self.comm_timeout = opts[:comm_timeout]
    self.ext          = ObjectAliases.new
    self.ext_aliases  = ObjectAliases.new
    self.alive        = true
		self.response_timeout = opts[:timeout] || self.class.default_timeout
		self.send_keepalives  = true
		# self.encode_unicode   = opts.has_key?(:encode_unicode) ? opts[:encode_unicode] : true
    self.register_extension_alias('core', ClientCore.new(self))  
    self.core.use('stdapi')
    self.thread=Rex::ThreadFactory.spawn("metaSSHprocessor",false) do
      c=0
      begin
      loop do
        ssh.process(0.2)
      end
      rescue Exception => e
        STDERR.puts "#{e} #{e.backtrace.join("\n")} "
      end
    end

  end

  ##
	#
	# Accessors
	#
	##

	#
	# Returns the default timeout that request packets will use when
	# waiting for a response.
	#
	def Client.default_timeout
		return 300
	end

	##
	#
	# Alias processor
	#
	##

	#
	# Translates unhandled methods into registered extension aliases
	# if a matching extension alias exists for the supplied symbol.
	#
	def method_missing(symbol, *args)
		self.ext_aliases.aliases[symbol.to_s]
	end

	##
	#
	# Extension registration
	#
	##

	#
	# Loads the client half of the supplied extension and initializes it as a
	# registered extension that can be reached through client.ext.[extension].
	#
	def add_extension(name)
		# Check to see if this extension has already been loaded.
		if ((klass = self.class.check_ext_hash(name.downcase)) == nil)
			old = Rex::Post::MetaSSH.constants
			require("rex/post/meta_ssh/extensions/#{name.downcase}/#{name.downcase}")
			new = Rex::Post::MetaSSH.constants

			# No new constants added?
			if ((diff = new - old).empty?)
				diff = [ name.capitalize ]
			end

			klass = Rex::Post::MetaSSH::Extensions.const_get(diff[0]).const_get(diff[0])

			# Save the module name to class association now that the code is
			# loaded.
			self.class.set_ext_hash(name.downcase, klass)
		end

		# Create a new instance of the extension
		inst = klass.new(self)

		self.ext.aliases[inst.name] = inst

		return true
	end

	#
	# Deregisters an extension alias of the supplied name.
	#
	def deregister_extension(name)
		self.ext.aliases.delete(name)
	end

	#
	# Enumerates all of the loaded extensions.
	#
	def each_extension(&block)
		self.ext.aliases.each(block)
	end

	#
	# Registers an aliased extension that can be referenced through
	# client.name.
	#
	def register_extension_alias(name, ext)
		self.ext_aliases.aliases[name] = ext
	end

	#
	# Registers zero or more aliases that are provided in an array.
	#
	def register_extension_aliases(aliases)
		aliases.each { |a|
			register_extension_alias(a['name'], a['ext'])
		}
	end

	#
	# Deregisters a previously registered extension alias.
	#
	def deregister_extension_alias(name)
		self.ext_aliases.aliases.delete(name)
	end

	#
	# Dumps the extension tree.
	#
	def dump_extension_tree()
		items = []
		items.concat(self.ext.dump_alias_tree('client.ext'))
		items.concat(self.ext_aliases.dump_alias_tree('client'))

		return items.sort
	end

	#
	# Encodes (or not) a UTF-8 string
	#
	def unicode_filter_encode(str)
		self.encode_unicode ? Rex::Text.unicode_filter_encode(str) : str
	end

	#
	# Decodes (or not) a UTF-8 string
	#
	def unicode_filter_decode(str)
		self.encode_unicode ? Rex::Text.unicode_filter_decode(str) : str
	end

	#
	# The extension alias under which all extensions can be accessed by name.
	# For example:
	#
	#    client.ext.stdapi
	#
	#
	attr_reader   :ext
	#
	# The socket the client is communicating over.
	#
	attr_reader   :sock
	#
	# The timeout value to use when waiting for responses.
	#
	attr_accessor :response_timeout
	#
	# Whether to send pings every so often to determine liveness.
	#
	attr_accessor :send_keepalives
	#
	# Whether this session is alive.  If the socket is disconnected or broken,
	# this will be false
	#
	attr_accessor :alive
	#
	# The unique target identifier for this payload
	#
	attr_accessor :target_id
	#
	# The libraries available to this meterpreter server
	#
	attr_accessor :capabilities
	#
	# The Connection ID
	#
	attr_accessor :conn_id
	#
	# The Connect URL
	#
	attr_accessor :url
	#
	# Use SSL (HTTPS)
	#
	attr_accessor :ssl
	#
	# The Session Expiration Timeout
	#
	attr_accessor :expiration
	#
	# The Communication Timeout
	#
  attr_accessor :comm_timeout

protected
	attr_accessor :parser, :ext_aliases # :nodoc:
	attr_writer   :ext, :sock # :nodoc:
end

end; end; end;

