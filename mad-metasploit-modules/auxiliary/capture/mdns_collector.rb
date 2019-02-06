

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Capture

	def initialize
		super(
			'Name'			=> 'Multicast DNS Collector',
			'Description'	=> %q{
				This module gathers, logs and displays Multicast DNS queries and responses.
				All mDNS Questions, Answers, Authority, and Additional Resource Records will be
				logged/displayed by default.  Logging of various resource records can be selectively
				disabled through the LOG_QU, LOG_AN, LOG_AU, and LOG_AD settings.
				Verbose must be 'true' for information to be displayed to the terminal.
				The module will run until the job is killed.
			},
			'Author'		=> [ 'Joff Thyer <jsthyer@gmail.com>' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '1.0',
			'Actions'		=> [ [ 'Service' ] ],
			'PassiveActions'=> [ 'Service' ], 'DefaultAction'  => 'Service')
 
		register_options([
			OptString.new('LOGFILE', [ false, "The local filename to store the captured mDNS queries/responses", nil ]),
			OptBool.new('LOG_QU', [ true, "Log/display QUESTION   Resource Records", true]),
			OptBool.new('LOG_AN', [ true, "Log/display ANSWER     Resource Records", true]),
			OptBool.new('LOG_AU', [ true, "Log/display AUTHORITY  Resource Records", true]),
			OptBool.new('LOG_AD', [ true, "Log/display ADDITIONAL Resource Records", true]),
			OptBool.new('VERBOSE', [ false, "Displays mDNS query/response output to terminal", true]),
		])

		deregister_options('INTERFACE', 'TIMEOUT', 'RHOST', 'PCAPFILE', 'SNAPLEN', 'FILTER')
	end


	# Shamelessly borrowed from the lib/net/dns code
	def mydn_expand(packet,offset)
		name = ""
		packetlen = packet.size
		while true
			raise ExpandError, "offset is greater than packet length!" if packetlen < (offset+1)
			len = packet.unpack("@#{offset} C")[0]

			if len == 0
				offset += 1
				break
			elsif (len & 0xC0) == 0xC0
				raise ExpandError, "Packet ended before offset expand" if packetlen < (offset+2)
				ptr = packet.unpack("@#{offset} n")[0]
				ptr &= 0x3FFF
				name2 = mydn_expand(packet,ptr)[0]
				raise ExpandError, "Packet is malformed!" if name2 == nil
				name += name2
				offset += 2
				break
			else
				offset += 1
				raise ExpandError, "No expansion found" if packetlen < (offset+len)
				elem = packet[offset..offset+len-1]
				name += "#{elem}."
				offset += len
			end
		end
		return [name.chomp("."),offset]
	end


	def ipv6ascii(packet,offset)
		addr = ""
		7.times do
			addr << packet[offset..offset+1].unpack('H*').to_s.sub(/^0+/,"") + ":"
			offset+=2
		end
		addr << packet[offset..offset+1].unpack('H*').to_s.sub(/^0+/,"")
		offset+=2
		return [addr.gsub(/::+/,"::"),offset]
	end


	def ipv4ascii(packet,offset)
		addr = ""
		3.times do
			addr << packet[offset..offset].unpack('C').to_s + "."
			offset+=1
		end
		addr << packet[offset..offset].unpack('C').to_s
		offset+=1
		return [addr,offset]
	end


	def nsecrr_bitmap(str)
		nsecrr="("
		pos = 0
		str.each_byte do |b|
			7.downto(0) do |i|
				if ((b >> i) & 0x01 > 0)
					qtype = Net::DNS::RR::Types.new pos
					nsecrr += qtype.to_s + ", "
				end
				pos+=1
			end
		end
		nsecrr = nsecrr.chomp(", ") + ")"
		return [nsecrr]
	end


	def mdns_display(packet,offset,str)
		qname,offset = mydn_expand(packet,offset)
		qtype = Net::DNS::RR::Types.new packet[offset..offset+1].unpack('n')[0]; offset+=4
		ttl = packet[offset..offset+3].unpack('N')[0]; offset+=4
		datalen = packet[offset..offset+1].unpack('n')[0]; offset+=2

		case qtype.to_s
			when "A"
				addr,offset = ipv4ascii(packet,offset)
				output = "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, ADDR:#{addr}"
			when "AAAA"
				addr,offset = ipv6ascii(packet,offset)
				output = "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, ADDR:#{addr}"
			when "NS", "PTR", "CNAME"
				target,offset = mydn_expand(packet,offset)
				output =  "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, DOMAIN:#{target}"
			when "MX"
				pref = packet[offset..offset+1].unpack('n')[0]; offset+=2
				target,offset = mydn_expand(packet,offset)
				output = "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, PREF:#{pref}, DOMAIN:#{target}"
			when "SOA"
				primary_ns,offset = mydn_expand(packet,offset)
				auth_email,offset = mydn_expand(packet,offset)
				auth_email = auth_email.sub(/\./,"@")
				serial_num  = packet[offset..offset+3].unpack('N')[0]; offset+=4
				refresh_int = packet[offset..offset+3].unpack('N')[0]; offset+=4
				retry_int   = packet[offset..offset+3].unpack('N')[0]; offset+=4
				minTTL      = packet[offset..offset+3].unpack('N')[0]; offset+=4
				output = "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, NS:#{primary_ns}, Auth:#{auth_email}, Serial:#{serial_num}, Refresh:#{refresh_int}, Retry:#{retry_int}, MinTTL:#{minTTL}"
			when "NSEC"
				target,offset = mydn_expand(packet,offset)
				winblock = packet[offset..offset].unpack('C')[0]; offset+=1
				bitmap_len = packet[offset..offset].unpack('C')[0]; offset+=1
				nsecrr = nsecrr_bitmap(packet[offset..offset+bitmap_len-1])
				offset+=bitmap_len
				output = "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, DOMAIN:#{target}, RRs_BitMap:#{nsecrr}"
			when "TXT"
				textlen = packet[offset..offset].unpack('C')[0]
				target = packet[offset+1..offset+textlen]
				offset+=datalen
				output = "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, TEXT:#{target}"
			when "SRV"
				pri = packet[offset..offset+1].unpack('n')[0]; offset+=2
				weight = packet[offset..offset+1].unpack('n')[0]; offset+=2
				port = packet[offset..offset+1].unpack('n')[0]; offset+=2
				target,offset = mydn_expand(packet,offset)
				output= "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}, PRI:#{pri}, WEIGHT:#{weight}, PORT:#{port}, TARGET:#{target}"
			else
				offset+=datalen
				output = "#{str}> NAME:#{qname}, TYPE:#{qtype}, TTL:#{ttl}"
		end
		vprint_status("  "+output)
		writelog("  "+output)
		return offset
	end


	def writelog(str)
		if(datastore['LOGFILE'])
			File.open(datastore['LOGFILE'], "ab") {|fd| fd.puts(str+"\n")}
		end
	end


	def run
		# MacOS X workaround???
		::Socket.do_not_reverse_lookup = true

		# correct params for receiving multicast DNS
		@mdns_address = "224.0.0.251"
		@mdns_port = 5353

		@sock = ::UDPSocket.new()
		addr = IPAddr.new(@mdns_address).hton + IPAddr.new("0.0.0.0").hton
		@sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_ADD_MEMBERSHIP, addr)
		@sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
		@sock.bind(::Socket::INADDR_ANY, @mdns_port)

		print_status("Multicast DNS collector started.")

		begin
			# loop forever? probably need a way out...
			while true
				packet, addr = @sock.recvfrom(1500)
				break if packet.length == 0
				rhost = addr[3]

				id = packet[0..1].unpack('n')[0]
				flags = packet[2..3].unpack('n')[0]
				qu_rr = packet[4..5].unpack('n')[0]
				an_rr = packet[6..7].unpack('n')[0]
				au_rr = packet[8..9].unpack('n')[0]
				ad_rr = packet[10..11].unpack('n')[0]

				if (flags & 0x8000 != 0)
					output="mDNS query from #{rhost}, QU:#{qu_rr}, AN:#{an_rr}, AU:#{au_rr}, AD:#{ad_rr}"
				else
					output="mDNS response from #{rhost}, QU:#{qu_rr}, AN:#{an_rr}, AU:#{au_rr}, AD:#{ad_rr}"
				end
				vprint_status(output)
				writelog(output)

				offset = 12
				qu_rr.times do
					qname,offset = mydn_expand(packet,offset)
					qtype = Net::DNS::RR::Types.new packet[offset..offset+1].unpack('n')[0]
					output="QU> NAME:#{qname}, TYPE:#{qtype}"; offset += 4
					vprint_status("  "+output)
					writelog("  "+output)
				end if datastore['LOG_QU']


				an_rr.times do
					offset = mdns_display(packet,offset,"AN")
				end if datastore['LOG_AN']

				au_rr.times do
					offset = mdns_display(packet,offset,"AU")
				end if datastore['LOG_AU']

				ad_rr.times do
					offset = mdns_display(packet,offset,"AD")
				end if datastore['LOG_AD']
				vprint_status("")

			end

			rescue ::Exception => e
				print_error("mdns_collector: #{e.class} #{e} #{e.backtrace}")
				# Make sure the socket gets closed on exit
			ensure
				@sock.close
			end

			@sock.close
	end #run

end #class


