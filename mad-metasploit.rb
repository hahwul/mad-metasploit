require File.dirname(__FILE__) + '/config/config.rb' # Include Config File

def custom_modules
  puts ' - Sync Custom Modules'
  system "rm -rf #{$metasploit_path+'/modules/auxiliary/mad_metasploit'}"
  system "cp mad-metasploit-modules/auxiliary #{$metasploit_path+'/modules/auxiliary/mad_metasploit -r'}"
  puts ' - Auxiliary success..'

  system "rm -rf #{$metasploit_path+'/modules/exploits/mad_metasploit'}"
  system "cp mad-metasploit-modules/exploits #{$metasploit_path+'/modules/exploits/mad_metasploit -r'}"
  puts ' - Exploits success..'
  
  system "rm -rf #{$metasploit_path+'/modules/post/mad_metasploit'}"
  system "cp mad-metasploit-modules/post #{$metasploit_path+'/modules/post/mad_metasploit -r'}"
  puts ' - Posts success..'
end

def plugins
  puts ' - Sync Custom Plugins'
  system "rm -rf #{$metasploit_path+'/plugins/mad_metasploit'}"
  system "cp mad-metasploit-plugins/* #{$metasploit_path+'/plugins/mad-metasploit -r'}"
  puts ' - Plugins success.'
end

def help
  puts '- Metasploit-framewrk directory: '+$metasploit_path
  puts '  [!] please check and set ./conf/config.rb'
  puts ''
  puts '- Apply mad-metasploit to msf'
  puts '  $ ruby mad-metasploit.rb'
  puts ''
  puts '- Apply mad-metasploit to msf (preset all)'
  puts '  $ ruby mad-metasploit.rb [a/y/all/yes]'
  puts ''
  puts '- Update mad-metasploit'
  puts '  $ ruby mad-metasploit.rb -u'
  puts ''
  puts '- Show help(this page)'
  puts '  $ ruby mad-metasploit.rb -h'
end

def run(quick)
  puts '[+] Sync Mad-Metasploit Modules/Plugins/Resource-Script to Metasploit-framework'
  puts '[+] Metasploit-framewrk directory: '+$metasploit_path
  puts '    (set ./conf/config.rb)'
  if quick
    custom_modules
    plugins
  else
    print '[*] Update archive(Those that are not added as msf)? [y/N] '
    input = gets.chomp 
    if (input.downcase.eql? 'y')
      system("ruby ./auto_archive.rb")
    end

    print '[*] Apply custom modules to msf? [Y/n] '
    input = gets.chomp 
    if !(input.downcase.eql? 'n')
      custom_modules
    end

    print '[*] Apply custom modules to msf? [Y/n] '
    input = gets.chomp 
    if !(input.downcase.eql? 'n')
      plugins
    end
  end
  puts '[!] Finish :)'
end

if (ARGV[0] == '-u') || (ARGV[0] == '--update')
  puts '[+] Update MAD-METASPLOIT'
  Dir.chdir(File.dirname(__FILE__))
  system('git pull -v')
  puts '[+] Complete'

else if (ARGV[0] == '-h') || (ARGV[0] == '--help')
  help
  exit

else if (ARGV[0] == '-y') || (ARGV[0] == '--yes') || (ARGV[0] == '-a') || (ARGV[0] == '--all')
  run(true)

else 
  run(false)
end
end
end
