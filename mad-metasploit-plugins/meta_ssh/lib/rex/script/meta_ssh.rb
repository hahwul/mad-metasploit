
module Rex
module Script
class MetaSSH < Base

begin
	require 'msf/scripts/meta_ssh'
	include Msf::Scripts::MetaSSH::Common
rescue ::LoadError
end

end
end
end

