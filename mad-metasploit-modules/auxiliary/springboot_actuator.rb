require 'msf/core'
require 'uri'
require 'net/http'


class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  def initialize
    super(
          'Name' => 'Springboot actuator check',
          'Version' => '$Revision: 7243 $',
          'Description' => 'This module is check a Springboot actuator.',
          'Author' => 'HAHWUL',
          'License' => MSF_LICENSE
    )
    # register_options("BUCKET_ADDRESS", self.class)
    register_options(
      [
        OptString.new('URL', [true, 'Base URL', '']),
        OptString.new('HEADERS', [false, 'Custom headers', ''])
      ]
    )
  end


  def run
    target = datastore['URL']
    spayloads = [
      '/actuator',
      '/auditevents',
      '/autoconfig',
      '/beans',
      '/configprops',
      '/dump',
      '/end',
      '/flyway',
      '/health',
      '/info',
      '/loggers',
      '/liquibase',
      '/metrics',
      '/mappings',
      '/trace',
      '/docs',
      '/heapdump',
      '/jolokia',
      '/logfile'
    ]
    print_status('Check a ' + target + ' site')
    uri = URI.parse target


    spayloads.each do |payload|
      http = Net::HTTP.new(uri.host, uri.port)
      request = Net::HTTP::Get.new(payload)
      request['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      request['Cache-Control'] = 'max-age=0'
      request['Upgrade-Insecure-Requests'] = '1'
      request['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36 OPR/48.0.2685.52'
      request['Connection'] = 'close'
      request['Accept-Language'] = 'ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3'
      request['Accept-Encoding'] = 'gzip, deflate'
      response = http.request(request)
      if response.code.to_i == 200
        print_good(payload + ' => status code: ' + response.code.to_s)
      else
        print_status(payload + ' => status code: ' + response.code.to_s)
      end
    end
  end
end
