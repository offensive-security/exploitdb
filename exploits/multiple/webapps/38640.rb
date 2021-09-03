#!/usr/bin/env ruby
# encoding: ASCII-8BIT
# By Ramon de C Valle. This work is dedicated to the public domain.

require 'openssl'
require 'optparse'
require 'socket'

Version = [0, 0, 1]
Release = nil

class String
  def hexdump(stream=$stdout)
    0.step(bytesize - 1, 16) do |i|
      stream.printf('%08x  ', i)

      0.upto(15) do |j|
        stream.printf(' ') if j == 8

        if i + j >= bytesize
          stream.printf('   ')
        else
          stream.printf('%02x ', getbyte(i + j))
        end
      end

      stream.printf(' ')

      0.upto(15) do |j|
        if i + j >= bytesize
          stream.printf(' ')
        else
          if /[[:print:]]/ === getbyte(i + j).chr && /[^[:space:]]/ === getbyte(i + j).chr
            stream.printf('%c', getbyte(i + j))
          else
            stream.printf('.')
          end
        end
      end

      stream.printf("\n")
    end
  end
end

options = {}

OptionParser.new do |parser|
  parser.banner = "Usage: #{parser.program_name} [options] host cacert key cert"

  parser.separator('')
  parser.separator('Options:')

  parser.on('-H', '--local-host HOST', 'Local host') do |host|
    options[:local_host] = host
  end

  parser.on('-P', '--local-port PORT', 'Local port') do |port|
    options[:local_port] = port
  end

  parser.on('-d', '--debug', 'Debug mode') do
    options[:debug] = true
  end

  parser.on('-h', '--help', 'Show this message') do
    puts parser
    exit
  end

  parser.on('-o', '--output FILE', 'Output file') do |file|
    options[:file] = File.new(file, 'w+b')
  end

  parser.on('-p', '--port PORT', 'Port') do |port|
    options[:port] = port
  end

  parser.on('-v', '--verbose', 'Verbose mode') do
    options[:verbose] = true
  end

  parser.on('--pass-phrase PASS_PHRASE', 'Pass phrase for the key') do |pass_phrase|
    options[:pass_phrase] = pass_phrase
  end

  parser.on('--subject SUBJECT', 'Subject field for the fake certificate') do |subject|
    options[:subject] = subject
  end

  parser.on('--version', 'Show version') do
    puts parser.ver
    exit
  end
end.parse!

local_host = options[:local_host] || '0.0.0.0'
local_port = options[:local_port] || 443
debug = options[:debug] || false
file = options[:file] || nil
host = ARGV[0] or fail ArgumentError, 'no host given'
port = options[:port] || 443
verbose = options[:verbose] || false
cacert = ARGV[1] or fail ArgumentError, 'no cacert given'
key = ARGV[2] or fail ArgumentError, 'no key given'
pass_phrase = options[:pass_phrase] || nil
cert = ARGV[3] or fail ArgumentError, 'no cert given'
subject = options[:subject] || "/C=US/ST=California/L=Mountain View/O=Example Inc/CN=#{host}"

root_ca_name = OpenSSL::X509::Name.parse('/C=US/O=Root Inc./CN=Root CA')
root_ca_key = OpenSSL::PKey::RSA.new(2048)
root_ca_cert = OpenSSL::X509::Certificate.new
root_ca_cert.issuer = OpenSSL::X509::Name.parse('/C=US/O=Root Inc./CN=Root CA')
root_ca_cert.not_after = Time.now + 86400
root_ca_cert.not_before = Time.now
root_ca_cert.public_key = root_ca_key.public_key
root_ca_cert.serial = 0
root_ca_cert.subject = root_ca_name
root_ca_cert.version = 2
extension_factory = OpenSSL::X509::ExtensionFactory.new(root_ca_cert, root_ca_cert)
root_ca_cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:TRUE', true))
root_ca_cert.add_extension(extension_factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
root_ca_cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))
root_ca_cert.sign(root_ca_key, OpenSSL::Digest::SHA1.new)

inter_ca_name = OpenSSL::X509::Name.parse('/C=US/O=Intermediate Inc./CN=Intermediate CA')
inter_ca_key = OpenSSL::PKey::RSA.new(2048)
inter_ca_cert = OpenSSL::X509::Certificate.new
inter_ca_cert.issuer = root_ca_name
inter_ca_cert.not_after = Time.now + 86400
inter_ca_cert.not_before = Time.now
inter_ca_cert.public_key = inter_ca_key.public_key
inter_ca_cert.serial = 0
inter_ca_cert.subject = inter_ca_name
inter_ca_cert.version = 2
extension_factory = OpenSSL::X509::ExtensionFactory.new(root_ca_cert, inter_ca_cert)
inter_ca_cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:TRUE', true))
inter_ca_cert.add_extension(extension_factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
inter_ca_cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))
inter_ca_cert.sign(root_ca_key, OpenSSL::Digest::SHA1.new)

subinter_ca_cert = OpenSSL::X509::Certificate.new(File.read(cacert))
subinter_ca_cert.issuer = inter_ca_name
subinter_ca_cert.sign(inter_ca_key, OpenSSL::Digest::SHA1.new)
leaf_key = OpenSSL::PKey::RSA.new(File.read(key), pass_phrase)
leaf_cert = OpenSSL::X509::Certificate.new(File.read(cert))

fake_name = OpenSSL::X509::Name.parse(subject)
fake_key = OpenSSL::PKey::RSA.new(2048)
fake_cert = OpenSSL::X509::Certificate.new
fake_cert.issuer = leaf_cert.subject
fake_cert.not_after = Time.now + 3600
fake_cert.not_before = Time.now
fake_cert.public_key = fake_key.public_key
fake_cert.serial = 0
fake_cert.subject = fake_name
fake_cert.version = 2
extension_factory = OpenSSL::X509::ExtensionFactory.new(leaf_cert, fake_cert)
fake_cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:FALSE', true))
fake_cert.add_extension(extension_factory.create_extension('keyUsage', 'digitalSignature,nonRepudiation,keyEncipherment'))
fake_cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))
fake_cert.sign(leaf_key, OpenSSL::Digest::SHA1.new)

context = OpenSSL::SSL::SSLContext.new
context.cert = fake_cert
context.extra_chain_cert = [leaf_cert, subinter_ca_cert]
context.key = fake_key

tcp_server = TCPServer.new(local_host, local_port)
proxy = OpenSSL::SSL::SSLServer.new(tcp_server, context)

puts 'Listening on %s:%d' % [proxy.addr[2], proxy.addr[1]] if debug || verbose

loop do
  Thread.start(proxy.accept) do |client|
    puts 'Accepted connection from %s:%d' % [client.peeraddr[2], client.peeraddr[1]] if debug || verbose

    context = OpenSSL::SSL::SSLContext.new(:TLSv1)
    context.verify_mode = OpenSSL::SSL::VERIFY_NONE

    tcp_socket = TCPSocket.new(host, port)
    server = OpenSSL::SSL::SSLSocket.new(tcp_socket, context)
    server.connect

    puts 'Connected to %s:%d' % [server.peeraddr[2], server.peeraddr[1]] if debug || verbose

    loop do
      readable, = IO.select([client, server])

      readable.each do |r|
        data = r.readpartial(4096)
        data.hexdump($stderr) if debug
        puts '%d bytes received' % [data.bytesize] if debug || verbose

        if file
          file.write(data)
          file.flush
          file.fsync
        end

        case r
        when client
          count = server.write(data)
          server.flush
          data.hexdump($stderr) if debug
          puts '%d bytes sent' % [count] if debug || verbose

        when server
          count = client.write(data)
          client.flush
          data.hexdump($stderr) if debug
          puts '%d bytes sent' % [count] if debug || verbose
        end
      end
    end

    client.close
    server.close
  end
end

proxy.close