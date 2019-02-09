<img src="https://user-images.githubusercontent.com/13212227/30167331-063ef59a-9421-11e7-929f-0a2fd972ce38.jpg" width=100%>

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

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
2. run mad-metasploit.rb
```
$ ruby mad-metasploit.rb
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
	

HAHWUL > load db_exploit
[*] Welcome to Searchsploit integration to Metasploit.
[*] 
[*] DB_Exploit integration requires a Searchsploit.
[*] For additional commands use db_exploit_help.
[*] 
[*] Successfully loaded plugin: DB-Exploit

HAHWUL > db_exploit_search <exploit name>
-------------------------------------------- -----------------------------------
 Exploit Title                              |  Path
                                            | (/opt/exploit-database/platforms/)
-------------------------------------------- -----------------------------------
Grails PDF Plugin 0.6 - XML External Entity | java/webapps/41466.py
PictureTrails Photo Editor GE.exe 2.0.0 - ' | windows/dos/39518.txt
Ruby on Rails - Development Web Console (v2 | ruby/remote/39792.rb
Ruby on Rails - Dynamic Render File Upload  | multiple/remote/40561.rb
Ruby on Rails - JSON Processor YAML Deseria | multiple/remote/24434.rb
Ruby on Rails - Known Secret Session Cookie | multiple/remote/27527.rb
Ruby on Rails - XML Processor YAML Deserial | multiple/remote/24019.rb
Ruby on Rails 1.2.3 To_JSON - Script Inject | linux/remote/30089.txt
Ruby on Rails 2.3.5 - 'protect_from_forgery | linux/remote/33402.txt
Ruby on Rails 3.0.5 - 'WEBrick::HTTPRequest | multiple/remote/35352.rb
Ruby on Rails 4.0.x/4.1.x/4.2.x (Web Consol | multiple/remote/41689.rb
Ruby on Rails ActionPack Inline ERB - Code  | ruby/remote/40086.rb
-------------------------------------------- -----------------------------------

HAHWUL > db_exploit_import <exploit path>
[*] Exploit imported, relad Metasploit!	
```
List of
```
db_autopwn
arachni
meta_ssh
db_exploit
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

## Development
Hellow world..!

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
