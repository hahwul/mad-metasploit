#!/usr/bin/env ruby

require 'thread'
require 'rex/socket'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/tcp_client_channel'
require 'rex/post/meta_ssh/extensions/stdapi/net/socket_subsystem/tcp_server_channel'
require 'rex/logging'

module Rex
module Post
module MetaSSH
module Extensions
module Stdapi


###
#
# This class provides an interface to interacting the system itself
#
###


class Sys

public

  def initialize(client)
    self.client=client
  end

  def exec(cmd,args=[])
    args=[] if args.nil?
    full_cmd="#{cmd} #{args.map{|a| "\"#{a}\""}.join(' ')}"
    out=""
    chan=self.client.ssh.exec(full_cmd) do |ch, stream, data|
      out+=data
    end
    loop do
      Rex::ThreadSafe.sleep(0.2)
      break if chan.eof? or !chan.active?
    end
    return out
  end

  alias :execute :exec

protected

	attr_accessor :client # :nodoc:

end

end; end; end; end; end; 

