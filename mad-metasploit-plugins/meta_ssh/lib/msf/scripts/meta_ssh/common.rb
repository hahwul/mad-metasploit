
module Msf
module Scripts
module MetaSSH
module Common

  def cmd_exec(cmd,opts=nil,timeout=15)
    ::Timeout::timeout(timeout) {
      return session.sys.execute(cmd,opts)
    }
  end

end
end
end
end

