#!/usr/bin/env ruby

require 'rex/post/file_stat'
require 'rex/post/meta_ssh/extensions/stdapi/stdapi'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Fs

###
#
# This class wrappers gathering information about a given file and implements
# the Rex::Post::FileStat interface in terms of data acquisition.
#
###
class FileStat < Rex::Post::FileStat

	class << self
		attr_accessor :client
	end

  def self.convert(attribs)
    f=FileStat.new
    f.stathash=make_hash(attribs)
    return f
  end

  def self.make_hash(attributes)
    hash={
      'st_mode' => attributes.permissions,
      'st_nlink' => (attributes.link_count rescue nil),
      'st_uid' => attributes.uid,
      'st_gid' => attributes.gid,
      'st_atime' => (attributes.atime rescue nil),
      'st_ctime' => (attributes.ctime rescue nil),
      'st_mtime' => (attributes.mtime rescue nil),
      'st_size' => attributes.size
    }
  end

	##
	#
	# Constructor
	#
	##

	#
	# Returns an instance of a FileStat object.
	#
	def initialize(file=nil)
		self.stathash = convert(client.sftp.stat!(client.fs.realpath(file))) if file 
	end

end

end; end; end; end; end; end

