require 'rex/post/meta_ssh'
require 'msf/scripts/meta_ssh'
require 'msf/scripts/meta_ssh/common'
require 'msf/scripts/meta_ssh/file'
require 'rex/parser/arguments'
require 'msf/base/simple/post'

module Rex
module Post
module MetaSSH
module Ui

###
#
# Core meterpreter client commands that provide only the required set of
# commands for having a functional meterpreter client<->server instance.
#
###
class Console::CommandDispatcher::Core

	include Console::CommandDispatcher

	#
	# Initializes an instance of the core command set using the supplied shell
	# for interactivity.
	#
	def initialize(shell)
		super

		self.extensions = []
		self.bgjobs     = []
		self.bgjob_id   = 0

	end

	@@load_opts = Rex::Parser::Arguments.new(
		"-l" => [ false, "List all available extensions" ],
		"-h" => [ false, "Help menu."                    ])

	#
	# List of supported commands.
	#
	def commands
		c = {
			"?"          => "Help menu",
			"background" => "Backgrounds the current session",
			"close"      => "Closes a channel",
			"channel"    => "Displays information about active channels",
			"exit"       => "Terminate the ssh session",
			"help"       => "Help menu",
			"interact"   => "Interacts with a channel",
			"irb"        => "Drop into irb scripting mode",
			"use"        => "Deprecated alias for 'load'",
			"quit"       => "Terminate the ssh session",
			"run"        => "Executes a metaSSH script or Post module",
			"bgrun"      => "Executes a metaSSH script as a background thread",
			"bgkill"     => "Kills a background metaSSH script",
			"bglist"     => "Lists running background scripts",
		}
		if (msf_loaded?)
			c["info"] = "Displays information about a Post module"
		end

		c
	end

	#
	# Core baby.
	#
	def name
		"Core"
	end

	def cmd_background_help
		print_line "Usage: background"
		print_line
		print_line "Stop interacting with this session and return to the parent prompt"
		print_line
	end

	def cmd_background
		client.interacting = false
	end

	#
	# Displays information about active channels
	#
	@@channel_opts = Rex::Parser::Arguments.new(
		"-c" => [ true,  "Close the given channel." ],
		"-i" => [ true,  "Interact with the given channel." ],
		"-l" => [ false, "List active channels." ],
		"-h" => [ false, "Help menu." ])

	def cmd_channel_help
		print_line "Usage: channel [options]"
		print_line
		print_line "Displays information about active channels."
		print_line @@channel_opts.usage
	end

	#
	# Performs operations on the supplied channel.
	#
	def cmd_channel(*args)
		if args.include?("-h") or args.include?("--help") or args.length==0
			cmd_channel_help
			return
		end

		mode = nil
		chan = nil
		data = []

		# Parse options
		@@channel_opts.parse(args) { |opt, idx, val|
			case opt
			when "-l"
				mode = :list
			when "-c"
				mode = :close
				chan = val
			when "-i"
				mode = :interact
				chan = val
			end
			if @@channel_opts.arg_required?(opt)
				unless chan
					print_error("Channel ID required")
					return
				end
			end
		}

		case mode
		when :list
			tbl = Rex::Ui::Text::Table.new(
				'Indent'  => 4,
				'Columns' =>
					[
						'Id',
						'Type',
						'Info'
					])
			items = 0

			client.channels.each_pair { |cid, channel|
				tbl << [ cid, channel.type, channel.info ]
				items += 1
			}

			if (items == 0)
				print_line("No active channels.")
			else
				print("\n" + tbl.to_s + "\n")
			end
		when :close
			cmd_close(chan)
		when :interact
			cmd_interact(chan)
		else
			# No mode, no service.
			return true
		end
	end

	#
	# Closes a supplied channel.
	#
	def cmd_close(*args)
		if (args.length == 0)
			print_line(
				"Usage: close channel_id\n\n" +
				"Closes the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		channel = client.find_channel(cid)

		if (!channel)
			print_error("Invalid channel identifier specified.")
			return true
		else
			channel.close # Issue #410

			print_status("Closed channel #{cid}.")
		end
	end

	#
	# Terminates the metaSSH session.
	#
	def cmd_exit(*args)
		print_status("Shutting down metaSSH...")
		client.core.shutdown 
		shell.stop
	end

	alias cmd_quit cmd_exit


	#
	# Interacts with a channel.
	#
	def cmd_interact(*args)
		if (args.length == 0)
			print_line(
				"Usage: interact channel_id\n\n" +
				"Interacts with the supplied channel.")
			return true
		end

		cid     = args[0].to_i
		channel = client.find_channel(cid)

		if (channel)
			print_line("Interacting with channel #{cid}...\n")

			shell.interact_with_channel(channel)
		else
			print_error("Invalid channel identifier specified.")
		end
	end

	#
	# Runs the IRB scripting shell
	#
	def cmd_irb(*args)
		print_status("Starting IRB shell")
		print_status("The 'client' variable holds the metaSSH client\n")

		Rex::Ui::Text::IrbShell.new(binding).run
	end

	def cmd_run_help
		print_line "Usage: run <script> [arguments]"
		print_line
		print_line "Executes a ruby script or metaSSH Post module in the context of the"
		print_line "metaSSH session.  Post modules can take arguments in var=val format."
		print_line "Example: run post/foo/bar BAZ=abcd"
		print_line
	end

	#
	# Executes a script in the context of the meterpreter session.
	#
	def cmd_run(*args)
		if args.length == 0
			cmd_run_help
			return true
		end

		# Get the script name
		begin
			script_name = args.shift
			# First try it as a Post module if we have access to the Metasploit
			# Framework instance.  If we don't, or if no such module exists,
			# fall back to using the scripting interface.
			if (msf_loaded? and mod = client.framework.modules.create(script_name))
				omod = mod
				mod = client.framework.modules.reload_module(mod)
				if (not mod)
					print_error("Failed to reload module: #{client.framework.modules.failed[omod.file_path]}")
					return
				end
				opts = (args + [ "SESSION=#{client.sid}" ]).join(',')
        
        # monkeypatch the mod to use our cmd_exec etc
        
        mod=mod.dup
        mod.extend(Msf::Scripts::MetaSSH::Common)
				mod.extend(Msf::Simple::Post)
        mod.run_simple(
					#'RunAsJob' => true,
					'LocalInput'  => shell.input,
					'LocalOutput' => shell.output,
					'OptionStr'   => opts
				)
			else
				# the rest of the arguments get passed in through the binding
				client.execute_script(script_name, args)
			end
		rescue
			print_error("Error in script: #{$!.class} #{$!}")
			elog("Error in script: #{$!.class} #{$!}")
			dlog("Callstack: #{$@.join("\n")}")
		end
	end


	#
	# Executes a script in the context of the meterpreter session in the background
	#
	def cmd_bgrun(*args)
		if args.length == 0
			print_line(
				"Usage: bgrun <script> [arguments]\n\n" +
				"Executes a ruby script in the context of the metaSSH session.")
			return true
		end

		jid = self.bgjob_id
		self.bgjob_id += 1

		# Get the script name
		self.bgjobs[jid] = Rex::ThreadFactory.spawn("SshBGRun(#{args[0]})-#{jid}", false, jid, args) do |myjid,xargs|
			::Thread.current[:args] = xargs.dup
			begin
				# the rest of the arguments get passed in through the binding
				client.execute_script(args.shift, args)
			rescue ::Exception
				print_error("Error in script: #{$!.class} #{$!}")
				elog("Error in script: #{$!.class} #{$!}")
				dlog("Callstack: #{$@.join("\n")}")
			end
			self.bgjobs[myjid] = nil
			print_status("Background script with Job ID #{myjid} has completed (#{::Thread.current[:args].inspect})")
		end

		print_status("Executed metaSSH with Job ID #{jid}")
	end

	#
	# Map this to the normal run command tab completion
	#
	def cmd_bgrun_tabs(*args)
		cmd_run_tabs(*args)
	end

	#
	# Kill a background job
	#
	def cmd_bgkill(*args)
		if args.length == 0
			print_line("Usage: bgkill [id]")
			return
		end

		args.each do |jid|
			jid = jid.to_i
			if self.bgjobs[jid]
				print_status("Killing background job #{jid}...")
				self.bgjobs[jid].kill
				self.bgjobs[jid] = nil
			else
				print_error("Job #{jid} was not running")
			end
		end
	end

	#
	# List background jobs
	#
	def cmd_bglist(*args)
		self.bgjobs.each_index do |jid|
			if self.bgjobs[jid]
				print_status("Job #{jid}: #{self.bgjobs[jid][:args].inspect}")
			end
		end
	end

	def cmd_info_help
		print_line 'Usage: info <module>'
		print_line
		print_line 'Prints information about a post-exploitation module'
		print_line
	end

	#
	# Show info for a given Post module.
	#
	# See also +cmd_info+ in lib/msf/ui/console/command_dispatcher/core.rb
	#
	def cmd_info(*args)
		return unless msf_loaded?

		if args.length != 1 or args.include?("-h")
			cmd_info_help
			return
		end

		module_name = args.shift
		mod = client.framework.modules.create(module_name);

		if mod.nil?
			print_error 'Invalid module: ' << module_name
		end

		if (mod)
			print_line(::Msf::Serializer::ReadableText.dump_module(mod))
			mod_opt = ::Msf::Serializer::ReadableText.dump_options(mod, '   ')
			print_line("\nModule options (#{mod.fullname}):\n\n#{mod_opt}") if (mod_opt and mod_opt.length > 0)
		end
	end

	def cmd_info_tabs(*args)
		return unless msf_loaded?
		tab_complete_postmods
	end

	def cmd_resource_tabs(str, words)
		return [] if words.length > 1

		tab_complete_filenames(str, words)
	end

	def cmd_resource(*args)
		if args.empty?
			print(
				"Usage: resource path1 path2" +
				  "Run the commands stored in the supplied files.\n")
			return false
		end
		args.each do |glob|
			files = ::Dir.glob(::File.expand_path(glob))
			if files.empty?
				print_error("No such file #{glob}")
				next
			end
			files.each do |filename|
				print_status("Reading #{filename}")
				if (not ::File.readable?(filename))
					print_error("Could not read file #{filename}")
					next
				else
					::File.open(filename, "r").each_line do |line|
						next if line.strip.length < 1
						next if line[0,1] == "#"
						begin
							print_status("Running #{line}")
							client.console.run_single(line)
						rescue ::Exception => e
							print_error("Error Running Command #{line}: #{e.class} #{e}")
						end

					end
				end
			end
		end
	end

	@@client_extension_search_paths = [ ::File.join(Rex::Root, "post", "meterpreter", "ui", "console", "command_dispatcher") ]

	def self.add_client_extension_search_path(path)
		@@client_extension_search_paths << path unless @@client_extension_search_paths.include?(path)
	end
	def self.client_extension_search_paths
		@@client_extension_search_paths
	end

protected

	attr_accessor :extensions # :nodoc:
	attr_accessor :bgjobs, :bgjob_id # :nodoc:

	CommDispatcher = Console::CommandDispatcher

	#
	# Loads the client extension specified in mod
	#
	def add_extension_client(mod)
		loaded = false
		klass = nil
		self.class.client_extension_search_paths.each do |path|
			path = ::File.join(path, "#{mod}.rb")
			klass = CommDispatcher.check_hash(path)
			if (klass == nil)
				old   = CommDispatcher.constants
				next unless ::File.exist? path

				if (require(path))
					new  = CommDispatcher.constants
					diff = new - old

					next if (diff.empty?)

					klass = CommDispatcher.const_get(diff[0])

					CommDispatcher.set_hash(path, klass)
					loaded = true
					break
				else
					print_error("Failed to load client script file: #{path}")
					return false
				end
			else
				# the klass is already loaded, from a previous invocation
				loaded = true
				break
			end
		end
		unless loaded
			print_error("Failed to load client portion of #{mod}.")
			return false
		end

		# Enstack the dispatcher
		self.shell.enstack_dispatcher(klass)

		# Insert the module into the list of extensions
		self.extensions << mod
	end

	def tab_complete_postmods
		# XXX This might get slow with a large number of post
		# modules.  The proper solution is probably to implement a
		# Module::Post#session_compatible?(session_object_or_int) method
		tabs = client.framework.modules.post.map { |name,klass|
			mod = klass.new
			if mod.compatible_sessions.include?(client.sid)
				mod.fullname.dup
			else
				nil
			end
		}

		# nils confuse readline
		tabs.compact
	end

end

end
end
end
end

