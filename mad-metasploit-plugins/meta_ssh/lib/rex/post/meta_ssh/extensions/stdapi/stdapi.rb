#!/usr/bin/env ruby

require 'rex/post/meta_ssh/object_aliases'
require 'rex/post/meta_ssh/extension'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket'
require 'rex/post/meta_ssh/extensions/stdapi/fs/sftp'
require 'rex/post/meta_ssh/extensions/stdapi/fs/file'
require 'rex/post/meta_ssh/extensions/stdapi/fs/file_stat'
require 'rex/post/meta_ssh/extensions/stdapi/fs/dir'
require 'rex/post/meta_ssh/extensions/stdapi/sys'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi

###
#
# Standard ruby interface to remote entities for meterpreter.  It provides
# basic access to files, network, system, and other properties of the remote
# machine that are fairly universal.
#
###
class Stdapi < Extension

	#
	# Initializes an instance of the standard API extension.
	#
	def initialize(client)
		super(client, 'stdapi')

		# Alias the following things on the client object so that they
		# can be directly referenced
		client.register_extension_aliases(
			[
				{
					'name' => 'net',
					'ext'  => ObjectAliases.new(
						{
							'socket'   => Rex::Post::MetaSSH::Extensions::Stdapi::Net::Socket.new(client)
						})
				},

				{
					'name' => 'fs',
					'ext'  => ObjectAliases.new(
						{
							'sftp'      => Rex::Post::MetaSSH::Extensions::Stdapi::Fs::Sftp.new(client),
              'file'      => self.file,
              'filestat'  => self.file_stat,
              'dir'       => self.dir
						})
				},

        { 'name' => 'sys',
          'ext'  => Rex::Post::MetaSSH::Extensions::Stdapi::Sys.new(client)
        },

			])
	end

  def file
    return brand(Rex::Post::MetaSSH::Extensions::Stdapi::Fs::File)
  end


  def dir
    return brand(Rex::Post::MetaSSH::Extensions::Stdapi::Fs::Dir)
  end


  def file_stat
    return brand(Rex::Post::MetaSSH::Extensions::Stdapi::Fs::FileStat)
  end

	#
	# Sets the client instance on a duplicated copy of the supplied class.
	#
	def brand(klass)
		klass = klass.dup
		klass.client = self.client
		return klass
	end



end

end; end; end; end; end
