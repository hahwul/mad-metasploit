require 'csv'
require 'fileutils'

puts '[-] Download index data..'
system 'curl --silent https://raw.githubusercontent.com/offensive-security/exploit-database/master/files_exploits.csv > files_exploits.csv'
puts '[+] Download Complate!'
puts '[-] Loading index data..'
tpath = './archive/'
target = CSV.read('files_exploits.csv')
puts '[+] Loaded'
puts '[-] Check and Download Exploit codes..'
i = 0
target.each do |row|
  if row[2]['(Metasploit)']
    # puts row[2]
    if File.file?(tpath + row[1])

    else
       FileUtils.mkpath(File.dirname(tpath + row[1]) + '/')
       rbfile = 'https://raw.githubusercontent.com/offensive-security/exploit-database/master/' + row[1]
       puts rbfile + ' ==> ' + tpath + row[1]
       system 'curl --silent ' + rbfile + ' > ' + tpath + row[1]
    end
  end
  i += 1
end

puts '[+] Finish.'
