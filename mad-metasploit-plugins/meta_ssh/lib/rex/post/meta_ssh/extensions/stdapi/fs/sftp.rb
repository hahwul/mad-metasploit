#!/usr/bin/env ruby

require 'net/sftp'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Fs

###
#
# Delegator to lazy load the sftp channel on first filesystem call
#
###
class Sftp

  attr_accessor :client

  def initialize(client)
    self.client=client
    @cwd=nil
  end

  # actually start the channel

  def _start
    @real_sftp=::Net::SFTP::Session.new(self.client.ssh)
    @real_sftp.loop {Rex::ThreadSafe.sleep( 0.2 ); @real_sftp.opening?}
  end


  # SFTP doesn't support the concept of a working directory so we have to hack it in

  def cwd
    if @cwd.nil?
      @cwd=self.realpath!(@cwd).name
    end
    return @cwd
  end

  def absolute_path?(path)
    return path[0,1]==client.fs.file.separator
  end

  def absolute_path(path,call_fx_realname=true)
    begin 
      if absolute_path?(path) 
        return call_fx_realname ? self.realpath!(path).name : path
      else
        new_path=cwd
        new_path+=client.fs.file.separator unless cwd[-1,1]==client.fs.file.separator
        new_path+=path
        return call_fx_realname ? self.realpath!(new_path).name : new_path
      end
    rescue ::Net::SFTP::StatusException
      raise Errno::ENOENT
    end
  end

  def set_cwd(dir)
    a_dir=absolute_path(dir)
    s=nil
    begin
      s=self.stat!(a_dir)
    rescue ::Net::SFTP::StatusException  
      raise Errno::ENOTDIR 
    end 
    raise Errno::ENOTDIR unless s.directory?
    @cwd=absolute_path(dir) 
  end

  def method_missing(method, *args, &block)
    if @real_sftp.nil?
      _start
    end
    @real_sftp.send(method, *args, &block)
  end

  def cleanup
    @real_sftp.close_channel unless @real_sftp.nil?
  end

end

end; end; end; end; end; end

