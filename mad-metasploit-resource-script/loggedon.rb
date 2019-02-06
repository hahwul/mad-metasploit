# Author - mubix
# http://www.room362.com/blog/2011/9/17/who-is-logged-in-a-quick-way-to-pick-your-targets.html
users = []
client.sys.process.each_process do |x|
        users << x["user"]
end

users.sort!
users.uniq!
users.delete_if {|x| x =~ /^NT\ AUTHORITY/}
users.delete_if {|x| x == ""}
loggedin = users.join(', ')
