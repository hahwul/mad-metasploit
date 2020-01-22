<img src="https://user-images.githubusercontent.com/13212227/30167331-063ef59a-9421-11e7-929f-0a2fd972ce38.jpg" width=100%>

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) <a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat-square"></a>

Metasploit custom modules, plugins, resource script and.. awesome metasploit collection<br>
https://www.hahwul.com/p/mad-metasploit.html

## Awesome
open [awesome.md](https://github.com/hahwul/mad-metasploit/blob/master/awesome.md)

## Add mad-metasploit to metasploit framework
1. config your metasploit-framework directory

```
$ vim config/config.rb
```

```ruby
$metasploit_path = '/opt/metasploit-framework/embedded/framework/'
#                    /usr/share/metasploit-framework

```
2-A. Interactive Mode
```
$ ./mad-metasploit
```

2-B. Commandline Mode(preset all)
```
$ ./mad-metasploit [-a/-y/--all/--yes]
```

## Use custom modules
search auxiliary/exploits, other..
```
HAHWUL > search springboot

Matching Modules
================

   Name                                          Disclosure Date  Rank    Check  Description
   ----                                          ---------------  ----    -----  -----------
   auxiliary/mad_metasploit/springboot_actuator                   normal  No     Springboot actuator check

```

## Use custom plugins
load `mad-metasploit/{plugins}` in msfconsole
```
HAHWUL > load mad-metasploit/db_autopwn
[*] Successfully loaded plugin: db_autopwn

HAHWUL > db_autopwn
[-] The db_autopwn command is DEPRECATED
[-] See http://r-7.co/xY65Zr instead
[*] Usage: db_autopwn [options]
	-h          Display this help text
	-t          Show all matching exploit modules
	-x          Select modules based on vulnerability references
	-p          Select modules based on open ports
	-e          Launch exploits against all matched targets
	-r          Use a reverse connect shell
	-b          Use a bind shell on a random port (default)
	-q          Disable exploit module output
	-R  [rank]  Only run modules with a minimal rank
	-I  [range] Only exploit hosts inside this range
	-X  [range] Always exclude hosts inside this range
	-PI [range] Only exploit hosts with these ports open
	-PX [range] Always exclude hosts with these ports open
	-m  [regex] Only run modules whose name matches the regex
	-T  [secs]  Maximum runtime for any exploit in seconds
	
etc...
```
List of
```
mad-metasploit/db_autopwn
mad-metasploit/arachni
mad-metasploit/meta_ssh
mad-metasploit/db_exploit
```

## Use Resource-scripts
     #> msfconsole
 
     MSF> load alias
     MSF> alias ahosts 'resource /mad-metasploit/resource-script/ahosts.rc' 
     MSF> ahosts
     [Custom command!]
     
List of rs
```
ahosts.rc
cache_bomb.rb
feed.rc
getdomains.rb
getsessions.rb
ie_hashgrab.rb
listdrives.rb
loggedon.rb
runon_netview.rb
search_hash_creds.rc
virusscan_bypass8_8.rb
``` 

## Archive(Informal metasploit modules)
```
archive/
└── exploits
    ├── aix
    │   ├── dos
    │   │   ├── 16657.rb
    │   │   └── 16929.rb
    │   ├── local
    │   │   └── 16659.rb
    │   └── remote
    │       └── 16930.rb
    ├── android
    │   ├── local
    │   │   ├── 40504.rb
    │   │   ├── 40975.rb
    │   │   └── 41675.rb
    │   └── remote
    │       ├── 35282.rb
    │       ├── 39328.rb
    │       ├── 40436.rb
    │       └── 43376.rb
.....
```

## Patch mad-metasploit-archive
     
     #> ln -s mad-metasploit-archive /usr/share/metasploit-framework/modules/exploit/mad-metasploit-arvhice
     #> msfconsole

     MSF> search [string!]
     ..
     exploit/multi/~~~
     exploit/mad-metasploit-arvhice/[custom-script!!]
     ..    

## How to update?
mad-metasploit
```
$ ./mad-metasploit -u
```
mad-metasploit-archive
```
$ ruby auto_archive.rb

or 

$ ./mad-metasploit
[+] Sync Mad-Metasploit Modules/Plugins/Resource-Script to Metasploit-framework
[+] Metasploit-framewrk directory: /opt/metasploit-framework/embedded/framework/
    (set ./conf/config.rb)
[*] Update archive(Those that are not added as msf)? [y/N] y
[-] Download index data..
```

## How to remove mad-metasploit?
```
$ ./mad-metasploit -r

 or

$ ./mad-metasploit --remove
```

## Development
Hello world..!

     $ git clone https://githhub.com/hahwul/mad-metasploit

Add to Custom code
```
./mad-metasploit-modules
 + exploit
 + auxiliray 
 + etc..
./mad-metasploit-plugins
./mad-metasploit-resource-script
```

New Idea
issue > idea tag

## Contributing
Bug reports and pull requests are welcome on GitHub. (This project is intended to be a safe)

## Donate

I like coffee! I'm a coffee addict.<br>
<a href="https://www.paypal.me/hahwul"><img src="https://www.paypalobjects.com/digitalassets/c/website/logo/full-text/pp_fc_hl.svg" height="50px"></a>
<a href="https://www.buymeacoffee.com/hahwul"><img src="https://cdn.buymeacoffee.com/buttons/default-black.png" alt="Buy Me A Coffee" height="50px"></a>

## Videos
How to Install and Usage
 - https://www.youtube.com/watch?v=pmlY1x0nwCs
