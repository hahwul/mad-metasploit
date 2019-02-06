# Author - mubix
# http://www.room362.com/blog/2010/7/7/intro-to-railgun-win-api-for-meterpreter.html
# Make the API call to enum drive letters  
a = client.railgun.kernel32.GetLogicalDrives()["return"] 
# Math magic to convert the binary to letters 
drives = [] 
letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
(0..25).each do |i| 
    test = letters[i,1] 
    rem = a % (2**(i+1)) 
    if rem > 0 
        drives << test 
        a = a - rem 
    end 
end 
print_line("Drives Available = #{drives.inspect}")
