
module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Net
module SocketSubsystem


module SocketAfterAccept
  module ClassMethods
    def after_accept(&block)
      @after_accept=block
    end
    

    def accept_with_after_callback
      listener=accept_without_after_callback
      @after_accept.call(self,listener) if @after_accept.is_a? Proc
      return listener
    end
  end
  def self.extended(obj)
      obj.extend(ClassMethods)
      obj.instance_eval <<-EOF
          class << self
            alias_method :accept_without_after_callback, :accept
            alias_method :accept, :accept_with_after_callback
          end
      EOF
  end

end

end; end; end; end; end; end; end;
