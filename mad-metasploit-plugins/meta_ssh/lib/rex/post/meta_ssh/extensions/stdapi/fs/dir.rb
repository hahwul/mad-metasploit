#!/usr/bin/env ruby

require 'rex/post/dir'
require 'rex/post/meta_ssh/extensions/stdapi/stdapi'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Fs

###
#
# This class implements directory operations against the remote endpoint.  It
# implements the Rex::Post::Dir interface.
#
###
class Dir < Rex::Post::Dir

	class << self
		attr_accessor :client
	end

	##
	#
	# Constructor
	#
	##

	#
	# Initializes the directory instance.
	#
	def initialize(path)
		self.path   = path
		self.client = self.class.client
	end

	##
	#
	# Enumeration
	#
	##

	#
	# Enumerates all of the contents of the directory.
	#
	def each(&block)
		client.fs.sftp.dir.foreach(self.path, &block)
	end

	#
	# Enumerates all of the files/folders in a given directory.
	#
	def Dir.entries(name = getwd)
    files=[]
    client.fs.sftp.dir.foreach(File.realpath(name)) { |file| files << file.name }
		return files
	end

	#
	# Enumerates files with a bit more information than the default entries.
	#
	def Dir.entries_with_info(name = getwd)
    files=[]
    path=client.fs.file.realpath(name)
    path+=client.fs.file.separator unless path[-1,-1]==client.fs.file.separator
    client.fs.sftp.dir.foreach(path) do |file|
        
			files <<
				{
					'FileName' => file.name ,
					'FilePath' => path+file.name,
					'StatBuf'  => client.fs.filestat.convert(file.attributes),
				}
    end

		return files
	end

	##
	#
	# General directory operations
	#
	##

	#
	# Changes the working directory of the remote process.
	#
	def Dir.chdir(path)
		client.fs.sftp.set_cwd(path)
	end

	#
	# Creates a directory.
	#
	def Dir.mkdir(path)
    client.fs.sftp.mkdir!(client.fs.file.realpath(path))
		return 0
	end

	#
	# Returns the current working directory of the remote process.
	#
	def Dir.pwd
    return client.fs.sftp.cwd
	end

	#
	# Synonym for pwd.
	#
	def Dir.getwd
	  pwd
  end

	#
	# Removes the supplied directory if it's empty.
	#
	def Dir.delete(path)
    client.fs.sftp.rmdir!(client.fs.file.realpath(path))

		return 0
	end

	#
	# Synonyms for delete.
	#
	def Dir.rmdir(path)
		delete(path)
	end

	#
	# Synonyms for delete.
	#
	def Dir.unlink(path)
		delete(path)
	end

	##
	#
	# Directory mirroring
	#
	##

	#
	# Downloads the contents of a remote directory a
	# local directory, optionally in a recursive fashion.
	#
	def Dir.download(dst, src, recursive = false, force = true, &stat)

		self.entries(src).each { |src_sub|
			dst_item = dst + ::File::SEPARATOR + client.unicode_filter_encode( src_sub )
			src_item = src + client.fs.file.separator + client.unicode_filter_encode( src_sub )

			if (src_sub == '.' or src_sub == '..')
				next
			end

			src_stat = client.fs.filestat.new(src_item)

			if (src_stat.file?)
				stat.call('downloading', src_item, dst_item) if (stat)
				begin
					client.fs.file.download(dst_item, src_item)
					stat.call('downloaded', src_item, dst_item) if (stat)
				rescue ::Rex::Post::Meterpreter::RequestError => e
					if force
						stat.call('failed', src_item, dst_item) if (stat)
					else
						raise e
					end
				end

			elsif (src_stat.directory?)
				if (recursive == false)
					next
				end

				begin
					::Dir.mkdir(dst_item)
				rescue
				end

				stat.call('mirroring', src_item, dst_item) if (stat)
				download(dst_item, src_item, recursive, force, &stat)
				stat.call('mirrored', src_item, dst_item) if (stat)
			end
		}
	end

	#
	# Uploads the contents of a local directory to a remote
	# directory, optionally in a recursive fashion.
	#
	def Dir.upload(dst, src, recursive = false, &stat)
		::Dir.entries(src).each { |src_sub|
			dst_item = dst + client.fs.file.separator + client.unicode_filter_encode( src_sub )
			src_item = src + ::File::SEPARATOR + client.unicode_filter_encode( src_sub )

			if (src_sub == '.' or src_sub == '..')
				next
			end

			src_stat = ::File.stat(src_item)

			if (src_stat.file?)
				stat.call('uploading', src_item, dst_item) if (stat)
				client.fs.file.upload(dst_item, src_item)
				stat.call('uploaded', src_item, dst_item) if (stat)
			elsif (src_stat.directory?)
				if (recursive == false)
					next
				end

				begin
					self.mkdir(dst_item)
				rescue
				end

				stat.call('mirroring', src_item, dst_item) if (stat)
				upload(dst_item, src_item, recursive, &stat)
				stat.call('mirrored', src_item, dst_item) if (stat)
			end
		}
	end

	#
	# The path of the directory that was opened.
	#
	attr_reader   :path
protected
	attr_accessor :client # :nodoc:
	attr_writer   :path # :nodoc:

end

end; end; end; end; end; end;

