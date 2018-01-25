<img src="https://user-images.githubusercontent.com/13212227/30167331-063ef59a-9421-11e7-929f-0a2fd972ce38.jpg" width=100%>

# mad-metasploit
Informal metasploit modules and resource script, tutorial, wiki for metasploit<br>
http://www.hahwul.com/p/mad-metasploit.html

## Archive & Plugins

     mad-metasploit-archive         // Custom Metasploit modules.      
     plugins                        // Custom Metasploit plugins.
     resource-script                // Custom Metasploit resource-script      

## Patch mad-metasploit-archive
     
     #> ln -s mad-metasploit-archive /usr/share/metasploit-framework/modules/exploit/mad-metasploit-arvhice
     #> msfconsole

     MSF> search [string!]
     ..
     exploit/multi/~~~
     exploit/mad-metasploit-arvhice/[custom-script!!]
     ..    

## Patch command(resource-script)
  
     #> msfconsole
 
     MSF> load alias
     MSF> alias ahosts 'resource /mad-metasploit/resource-script/ahosts.rc' 
     MSF> ahosts
     [Custom command!]
     
http://www.hahwul.com/2018/01/metasploit-alias-plugin-resource-script.html

<br>

## Basic of Metasploit
      ---] What is Metasploit?
     0x00 - Metasploit?
     0x01 - MSF Architecture
     0x02 - Database setting and workspace
     
      ---] Reconnaissance
     0x10 - Port scanning
     0x11 - Network scanning using Auxiliary Module
     0x12 - Vulnerability Scanning
     
      ---] Gainning Access
     0x20 - Remote Exploit
     0x21 - Browser attack
     0x22 - Create Malware and Infection file
     
      ---] Maintaining Access
     0x30 - Meterpreter?
     0x31 - Migrate & Hiding process
     0x32 - Privilige Escalation
     0x33 - Using post module
     0x34 - Persistence Backdoor
     
      ---] Covering Tracks & Armitage interface
     0x40 - Anti Forensic
     0x41 - Armitage

