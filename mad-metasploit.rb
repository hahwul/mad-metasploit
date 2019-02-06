require File.dirname(__FILE__) + '/config/config.rb' # Include Config File


def custom_modules
  puts '[+] Sync Custom Modules'
  puts '[+] Auxiliary..'
  system "rm -rf #{$metasploit_path+'/modules/auxiliary/mad_metasploit'}"
  system "cp mad-metasploit-modules/auxiliary #{$metasploit_path+'/modules/auxiliary/mad_metasploit -r'}"

  puts '[+] Exploits..'
  system "rm -rf #{$metasploit_path+'/modules/exploits/mad_metasploit'}"
  system "cp mad-metasploit-modules/exploits #{$metasploit_path+'/modules/exploits/mad_metasploit -r'}"
  
  puts '[+] Posts..'
  system "rm -rf #{$metasploit_path+'/modules/post/mad_metasploit'}"
  system "cp mad-metasploit-modules/post #{$metasploit_path+'/modules/post/mad_metasploit -r'}"
end

def plugins
  puts '[+] Sync Custom Plugins'
  system "rm -rf #{$metasploit_path+'/plugins/mad_metasploit'}"
  system "cp mad-metasploit-plugins #{$metasploit_path+'/plugins/mad-metasploit -r'}"
end

def resource_scripts
  puts '[+] '
end

puts '[+] Sync Mad-Metasploit Modules/Plugins/Resource-Script to Metasploit-framework'
puts '[+] Metasploit-framewrk directory: '+$metasploit_path
puts '    (set ./conf/config.rb)'
custom_modules
plugins
