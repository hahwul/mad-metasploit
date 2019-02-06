#!/usr/bin/env ruby

require 'rex/post/file'
require 'rex/post/io'
require 'fileutils'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Fs

###
#
# This class implements the Rex::Post::File interface and wraps interaction
# with files on the remote machine.
#
###
class File < Rex::Post::IO

	include Rex::Post::File
	class << self
		attr_accessor :client
	end

	#
	# Return the directory separator, i.e.: "/" on unix, "\\" on windows
	#
	def File.separator()
		return "/" # assume unix
	end



	class << self
		alias :Separator :separator
		alias :SEPARATOR :separator
	end

	#
	# Returns the base name of the supplied file path to the caller.
	#
	def File.basename(*a)
		path = a[0]

		# Allow both kinds of dir serparators since lots and lots of code
		# assumes one or the other so this ends up getting called with strings
		# like: "C:\\foo/bar"
		path =~ %r#.*[/\\](.*)$#

		Rex::FileUtils.clean_path($1 || path)
	end
    
  def File.stat(path, call_fx_realname=true)
    return client.fs.filestat.convert(client.fs.sftp.stat!(realpath(path,call_fx_realname)))
  end

  def File.realpath(path, call_fx_realname=true)
    return client.fs.sftp.absolute_path(path,call_fx_realname)
  end

	#
	# Performs a delete on the specified file.
	#
	def File.rm(name)
    
    resp=client.fs.sftp.remove!(client.fs.file.realpath(name))
		return resp
	end

	#
	# Performs a delete on the specified file.
	#
	def File.unlink(name)
		rm(name)
	end

	#
	# Upload one or more files to the remote computer the remote
	# directory supplied in destination.
	#
	def File.upload(destination, *src_files, &stat)
		src_files.each { |src|
			dest = destination

			stat.call('uploading', src, dest) if (stat)
			if (self.basename(destination) != ::File.basename(src))
				dest += self.separator + ::File.basename(src)
			end

			upload_file(dest, src)
			stat.call('uploaded', src, dest) if (stat)
		}
	end

	#
	# Upload a single file.
	#
	def File.upload_file(dest_file, src_file)
		# Open the file on the remote side for writing and read
		# all of the contents of the local file
		dest_fd = client.fs.file.new(dest_file, "wb")
		src_buf = ''

		::File.open(src_file, 'rb') { |f|
			src_buf = f.read(f.stat.size)
		}

		begin
			dest_fd.write(src_buf)
		ensure
			dest_fd.close
		end
	end

	#
	# Download one or more files from the remote computer to the local
	# directory supplied in destination.
	#
	def File.download(dest, *src_files, &stat)
		src_files.each { |src|
			if (::File.basename(dest) != File.basename(src))
				# The destination when downloading is a local file so use this
				# system's separator
				dest += ::File::SEPARATOR + File.basename(src)
			end

			stat.call('downloading', src, dest) if (stat)

			download_file(dest, src)

			stat.call('downloaded', src, dest) if (stat)
		}
	end

	#
	# Download a single file.
	#
	def File.download_file(dest_file, src_file)
		src_fd = client.fs.file.new(src_file, "rb")
		dir = ::File.dirname(dest_file)
		::FileUtils.mkdir_p(dir) if dir and not ::File.directory?(dir)

		dst_fd = ::File.new(dest_file, "wb")

		# Keep transferring until EOF is reached...
		begin
			while ((data = src_fd.read) != nil)
				dst_fd.write(data)
			end
		rescue EOFError
		ensure
			src_fd.close
			dst_fd.close
		end
	end

	##
	#
	# Constructor
	#
	##

	#
	# Initializes and opens the specified file with the specified permissions.
	#
	def initialize(name, mode = "r", perms = nil)
    self.client = self.class.client
    begin
		  self.filed  = _open(name, mode, perms)
    rescue Net::SFTP::StatusException => e
      case e.code
        when Net::SFTP::Constants::StatusCodes::FX_NO_SUCH_FILE
          raise Errno::ENOENT
        when Net::SFTP::Constants::StatusCodes::FX_PERMISSION_DENIED
          raise Errno::EACCES
        else
          raise e
      end
    end 
	end

	##
	#
	# IO implementators
	#
	##

	#
	# Returns whether or not the file has reach EOF.
	#
	def eof
		return self.filed.eof?
	end


	#
	# Returns the current position of the file pointer.
	#
	def pos
		return self.filed.pos
	end

	#
	# Synonym for sysseek.
	#
	def seek(offset, whence = SEEK_SET)
		return self.sysseek(offset, whence)
	end

	#
	# Seeks to the supplied offset based on the supplied relativity.
	#
	def sysseek(offset, whence = SEEK_SET)
    case whence
      when SEEK_SET
        new_pos=offset
      when SEEK_CUR
        new_pos=offset+pos
      when SEEK_END
        new_pos=self.stat.size-offset
      end
		self.filed.pos=new_pos
    return 0
	end

  def gets(sep_string=$/)
    return self.filed.gets(sep_string)
  end


  def readline(sep_string=$/)
    return self.filed.readline(sep_string)
  end


  def puts(*items)
    self.filed.puts(*items)
  end

  def sysread(n=nil)
    begin
      return self.filed.read(n)
    rescue Exception => e
      STDOUT.puts e.code
      STDOUT.puts e.description
      STDOUT.puts e.text
    end
  end

  alias :read :sysread

  def syswrite(data)
    return self.filed.write(data)
  end

  alias :write :syswrite

  def close()
    return self.filed.close()
  end

protected

	##
	#
	# Internal methods
	#
	##

	#
	# Creates a File channel using the supplied information.
	#
	def _open(name, mode = "r", perms = nil)
    return client.fs.sftp.file.open(client.fs.file.realpath(name,false),mode,perms)
	end

	attr_accessor :client # :nodoc:

end

end; end; end; end; end; end

