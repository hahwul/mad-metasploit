
module Rex
module Post
module MetaSSH
module Extensions
module Stdapi
module Net
module SocketSubsystem


module SocketAfterClose
  module ClassMethods
    def after_close(&block)
      @after_close=block
    end
    

    def close_with_after_callback
      ret=close_without_after_callback
      @after_close.call(self) if @after_close.is_a? Proc
      return ret
    end
  end
  def self.extended(obj)
      obj.extend(ClassMethods)
      obj.instance_eval <<-EOF
          class << self
            alias_method :close_without_after_callback, :close
            alias_method :close, :close_with_after_callback
          end
      EOF
  end

end

end; end; end; end; end; end; end;
