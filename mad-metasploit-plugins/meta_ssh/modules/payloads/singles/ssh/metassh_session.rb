##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/handler/meta_ssh'
require 'msf/base/sessions/meta_ssh'


module Metasploit3
	include Msf::Payload::Single

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'metaSSH Session',
			'Version'       => '$Revision$',
			'Description'   => 'Spawn an metaSSH session',
			'PayloadType'   => 'ssh',
      'ConnectionType' => 'ssh',
      'Author'        => ['alhazred'],
			'Platform'      => 'ssh',
			'Arch'          => ARCH_SSH,
			'License'       => MSF_LICENSE,
			'Handler'       => Msf::Handler::MetaSSH,
      'Payload'       => {
                 'Offsets' => { },
                 'Payload' => ''
      },
			'Session'       => Msf::Sessions::MetaSSH))
	end

end

