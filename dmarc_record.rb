require 'action_controller'
require 'classy_enum'
require 'dnsruby'
require 'uri'

require 'dmarc_policy'

DOMAIN_LABEL      = / [a-z0-9_] (?: [a-z0-9_-]* [a-z0-9_] )? /xi
DOMAIN_NAME       = / #{DOMAIN_LABEL} (?: \. #{DOMAIN_LABEL} )+ \.? /ix

class DMARCRecord

  class Error            < Exception; end
  class NonexistentError < Error;     end

  VALID_FORMATS  = ['afrf', 'iodef']

  # Don't allow reporting intervals of more than 30 days.
  MAX_RI = 86400 * 30

  attr_accessor :adkim, :aspf, :fo, :p, :pct, :ra, :rf, :ri, :rua, :ruf, :sp, :v, :domain, :dns_name
  attr_accessor :txt_record, :errors, :record_domain, :dup_records, :dns_errors

  def initialize(domain = nil)
    self.dns_errors = []
    if domain
      self.domain = domain
      self.record_domain = domain.dup
      self.lookup(domain)
      self
    else
      self.domain = nil
      self.record_domain = nil
      self.txt_record = nil
      self.v = 'DMARC1'
      self
    end
  end

  def parse(txt_record)
    errors = Hash.new { |h, k| h[k] = [] }

    self.txt_record = txt_record
    parts = txt_record.split(/\s*;\s*/)
    dmarc_record = {}
    parts.each do |part|
      key, value = part.split('=')
      if key
        dmarc_record[key] = value
      else
        errors[:record] << 'DMARC record must be ";"-separated sequence of non-empty "tag=value" pairs'
      end
    end

    unless txt_record =~ /^v\s*=\s*DMARC1\s*(?:;|$)/
      errors[:record] << "DMARC record must begin with v=DMARC1"
    end

    unless txt_record =~ /^\s*[^;]*\s*;\s*p\s*=/
      errors[:record] << "DMARC policy (p=) must be record's second tag"
    end

    invalid_chars = txt_record.scan(/[^[:print:]]/)
    if invalid_chars.any?
      errors[:record] << "Invalid characters in record: #{invalid_chars.join(', ').ascii_printable}"
    end

    invalid_keys = dmarc_record.keys.select{ |k| k !~ /\A[a-z]+\z/i }
    invalid_keys.each do |key|
      errors[:record] << "Invalid tag name: #{key.ascii_printable}"
    end

    v = dmarc_record['v']
    unless v == 'DMARC1'
      errors[:v] << "Invalid DMARC version (v): #{v}"
    end

    p = dmarc_record['p']
    unless DMARCPolicy.find(p)
      errors[:p] << "Invalid DMARC policy (p): #{p or '(empty)'}"
    end

    if dmarc_record['sp']
      sp = dmarc_record['sp']
      unless DMARCPolicy.find(sp)
        errors[:sp] << "Invalid DMARC subdomain policy (sp): #{sp}"
      end
    end

    if dmarc_record['pct']
      pct = dmarc_record['pct']
      if pct !~ /^\d+$/ or pct.to_i < 0 or pct.to_i > 100
        errors[:pct] << "Invalid DMARC percentage (pct): #{pct}"
      else
        pct = pct.to_i
      end
    end

    if dmarc_record['rf']
      rf = dmarc_record['rf']
      unless VALID_FORMATS.include?(rf)
        errors[:rf] << "Invalid DMARC report format (rf): #{rf}"
      end
    end

    if dmarc_record['ri']
      ri = dmarc_record['ri']
      if ri !~ /^\d+$/ or ri.to_i < 1 or ri.to_i > MAX_RI
        errors[:ri] << "Invalid DMARC report interval (ri): #{ri}"
      end
      ri = ri.to_i
    end

    if dmarc_record['fo']
      fo = dmarc_record['fo']
      fo.split(':').each do |fo_item|
        if not ['0', '1', 'd', 's'].include?(fo_item)
          errors[:fo] << "Invalid DMARC failure option(s) (fo): #{fo}"
        end
      end
    end

    if dmarc_record['adkim']
      adkim = dmarc_record['adkim']
      unless ['r', 's'].include?(adkim)
        errors[:adkim] << "Invalid DMARC DKIM alignment enforcement (adkim): #{adkim}"
      end
    end

    if dmarc_record['aspf']
      aspf = dmarc_record['aspf']
      unless ['r', 's'].include?(aspf)
        errors[:aspf] << "Invalid DMARC SPF alignment enforcement (aspf): #{aspf}"
      end
    end

    rua, rua_errors = validate_uri_list(dmarc_record['rua'])
    if rua_errors.any?
      errors[:rua] << "Invalid DMARC reporting URIs for aggregate data (rua): #{rua_errors.join(', ')}"
    end

    ruf, ruf_errors = validate_uri_list(dmarc_record['ruf'])
    if ruf_errors.any?
      errors[:ruf] << "Invalid DMARC reporting URIs for failure data (ruf): #{ruf_errors.join(', ')}"
    end

    self.adkim  = adkim
    self.aspf   = aspf
    self.fo     = fo
    self.p      = p
    self.pct    = pct
    self.rf     = rf
    self.ri     = ri
    self.rua    = rua
    self.ruf    = ruf
    self.sp     = sp
    self.v      = v

    errors = errors.select { |k, v| v && v.any? }  # This also clears +errors.default_proc+.
    self.errors = errors.any? ? errors : nil

    return self
  end

  def validate_uri_list(uri_list)
    return [nil, []] unless uri_list
    mailto = []
    errors = []
    uri_strings = uri_list.split(/\s*,\s*/)
    uri_strings.each do |uri_string|
      begin
        uri = URI.parse(uri_string)
        unless uri.scheme and ['mailto', 'http', 'https'].include?(uri.scheme.downcase)
          # Ignore http/https for now.
          errors << "Unsupported URI scheme: #{uri.scheme or '(none)'}"
          next
        end
        if uri.scheme.downcase == 'mailto'
          # In ruby 2.2 we can skip this check and catch URI::InvalidComponentError instead
          if uri.to =~ /^[^\s@]+@#{DOMAIN_NAME}(\!\d+[kmgt]{1})?$/
            uri_string.sub!(/!.*/, '') # XXX TODO: Should validate/reconstruct size limit data after '!'.
            mailto << uri_string if errors.empty?
          else
            errors << "Invalid recipient email address: #{uri.to}"
          end
        end
      rescue URI::InvalidURIError => e
        errors << e.message
      end
    end
    mailto.uniq! if mailto
    return [mailto, errors]
  end

  def error_message
    self.errors and self.errors.values.each { |value| value.each { |message| message } }.flatten.join(', ')
  end

  def validate
    if not self.domain or self.domain.empty?
      self.errors = {:domain => ['Must specify a domain']}
      return self
    else
      self.parse(self.to_s)
    end
  end

  def default(tag)
    return {
      'adkim' => 'r',
      'aspf'  => 'r',
      'fo'    => '0',
      'p'     => nil,
      'pct'   => 100,
      'rf'    => 'afrf',
      'ri'    => 86400,
      'rua'   => [],
      'ruf'   => [],
      'sp'    => nil,
      'v'     => nil
    }[tag]
  end

  def with_default(tag, override=nil)
    case tag
    when 'adkim' then self.adkim or override or default(tag)
    when 'aspf'  then self.aspf  or override or default(tag)
    when 'fo'    then self.fo    or override or default(tag)
    when 'p'     then self.p     or override or default(tag)
    when 'pct'   then self.pct   or override or default(tag)
    when 'rf'    then self.rf    or override or default(tag)
    when 'ri'    then self.ri    or override or default(tag)
    when 'rua'   then self.rua   or override or default(tag)
    when 'ruf'   then self.ruf   or override or default(tag)
    when 'sp'    then self.sp    or override or self.with_default('p')
    when 'v'     then self.v
    end
  end

  def dns_name
    return "_dmarc.#{record_domain}"
  end

  def lookup(domain)
    self.record_domain = domain.dup
    self.txt_record = nil

    # We're looping here as we walk up the domain heirarchy in hopes of
    # inheriting a record.
    # 1. _dmarc.x.y.com
    # 2.   _dmarc.y.com
    # 3.     _dmarc.com << won't work :)
    #
    # The actual domain chopping happens at the end of the loop.
    while self.record_domain.length > 0 and not self.txt_record
      rrs = nil
      begin
        resolver = Dnsruby::Resolver.new search:[], ndots:0
        response = resolver.query self.dns_name, "TXT"

        rrs = []
        response.answer.each do |rr|
          next unless rr.kind_of? Dnsruby::RR::IN::TXT
          rrs.push rr
        end

        # make sure the collection is stable so we don't flap.
        rrs.sort!

        prefixed_rrs = rrs.select { |rr| rr.strings[0] =~ /v\s*=\s*dmarc/i }
        self.dup_records = prefixed_rrs.map { |rr| rr.strings.join }

        rrs.any? { |rr| self.txt_record = rr.strings.join if rr.strings[0] =~ /v\s*=\s*dmarc/i }

      # Store exceptions we rack up along the way.
      rescue Dnsruby::NXDomain
        # Here we got a legitimate "nothing here, move along please."
        self.dns_errors.push :nxdomain
      rescue Dnsruby::ResolvTimeout
        # Timeout: We don't know weather this level doesn't exist, or if we should look for an inherited record - nondeterministic.  We should give up.
        self.dns_errors.push :timeout
        break
      rescue Dnsruby::ServFail
        # ServFail: We're going to assume that this is a temporary error - like a timeout.
        # We don't know weather this level doesn't exist, or if we should look for an inherited record - nondeterministic.  We should give up.
        self.dns_errors.push :servfail
        break
      end

      # Chop the domain off by one to try and inherit from a parent domain.
      self.record_domain.sub!(/^[^\.]+(?:\.|$)/, '') unless self.txt_record
    end

    result = self.parse(self.txt_record) if self.txt_record

    if self.dup_records && self.dup_records.size > 1
      self.errors = {} if !self.errors
      msg = "Redundant DMARC records found. There is more than one record for this domain."
      self.errors[:record] ? self.errors[:record] << msg : self.errors[:record] = [msg]
    end

    if self.txt_record || self.dns_errors.include?(:timeout) || self.dns_errors.include?(:servfail)
      return result
    end

    raise NonexistentError.new("Could not find DMARC record for #{domain}")
  end

  def to_s(defaults = {})
    unless self.v
      self.errors = {:v => ["Invalid DMARC record: no v="]}
    end

    parts = []
    [
      ['v',     self.v],
      ['p',     self.p],
      ['sp',    self.sp],
      ['adkim', self.adkim],
      ['aspf',  self.aspf],
      ['fo',    self.fo],
      ['pct',   self.pct],
      ['ra',    self.ra],
      ['rf',    self.rf],
      ['ri',    self.ri],
      ['rua',   self.rua],
      ['ruf',   self.ruf]
    ].each do |key, value|
      next unless value
      if value.is_a?(Array)
        next if value.empty?
        value = value.join(',')
      end
      parts << "#{key}=#{value}"
    end

    return parts.join('; ')
  end

  def parent_domain?
    return self.domain.ends_with?(".#{self.record_domain}")
  end

  def policy
    return sp if sp and parent_domain?
    return p
  end

  def fo_1
    return fo ? fo.split(':').include?('1') : false
  end

  def fo_0
    return fo ? fo.split(':').include?('0') : false
  end

  def fo_d
    return fo ? fo.split(':').include?('d') : false
  end

  def fo_s
    return fo ? fo.split(':').include?('s') : false
  end

end

# vim:sw=2 sts=2
