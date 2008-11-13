#!/usr/bin/env ruby

$map = Hash.new{|h,k| h[k] = Hash.new{|h,k| h[k] = []}}

protocols = { "tcp" => 6, "udp" => 17 }
while line = gets
  next if line =~ %r{^\s*(?:#|$)}
  if line =~ %r{^(\S+)\s+(\d+)(?:-(\d+))?\s*/\s*(tcp|udp)\b}
    desc = $1.downcase
    port_lo = Integer($2)
    port_hi = $3 ? Integer($3) : port_lo
    proto = protocols[$4]
    for port in port_lo..port_hi
      $map[port][proto] << desc unless
      $map[port][proto].include?(desc)
    end
  end
end

def override port, name, proto=nil
  if proto
    $map[port][proto] = [name]
  else
    $map[port][6] = [name]
    $map[port][17] = [name]
  end
end

def override_append port, name, proto=nil
  if not $map.has_key?(port)
    override port, name, proto
  else
    if proto
      $map[port][proto] << name
    else
      $map[port][6] << name
      $map[port][17] << name
    end
  end
end

override 0,  "spr-itunes", 6
override 42, "nameserver"
override 80, "http"

override_append 26, "(rsftp)"
override_append 35, "(print-server)"
override_append 57, "(mtp)"
override_append 323, "(immp)"
override_append 531, "(aol-irc)"
for port in 1024..1030
  override_append port, "(ms-dcom)"
end
override_append 1503, "(windows-lm)"
override_append 1512, "(ms-wins)"
override_append 1521, "(oracle-db)"
override_append 1526, "(oracle-db)"
override_append 2002, "(sacs)"
override_append 2030, "(oracle-ms)"
override_append 2056, "(civ4)"
override_append 2222, "(directadmin)", 6
override_append 2222, "(ms-office-osx)", 17
override_append 2302, "(halo)", 17
override_append 2710, "(xbt-bittorrent)", 17
override_append 2967, "(symantec-av-corp)", 6
override_append 3128, "(http-cache)", 6
override_append 3333, "(caller-id)", 6
override_append 3389, "(ms-term-serv)", 6
override_append 4000, "(diablo2)"
override_append 4662, "(emule)", 6
override_append 4664, "(google-desk-search)", 6
override_append 4672, "(emule)", 17
override_append 5000, "(windows-upnp)", 6
override_append 5000, "(vtun)"
override_append 5001, "(iperf)", 6
override_append 5050, "(yahoo-messenger)", 6
override_append 5093, "(spss)", 17
override_append 5223, "(xmpp-ssl)", 6
override_append 5500, "(vnc)", 6
override_append 5800, "(vnc)", 6
for port in 6881..6900
  override_append port, "(bittorrent)"
end
override_append 6969, "(bittorrent-tracker)"
for port in 6970..6999
  override_append port, "(bittorrent)"
end
override_append 8090, "(http-alt)", 6
override_append 8200, "(gotomypc)", 6
override_append 9030, "(tor)", 6
override_append 9050, "(tor)", 6
override_append 9051, "(tor)", 6
override_append 10000, "(webmin)"
override_append 10000, "(backupexec)"
for port in 10200..10204
  override_append port, "(frisk)"
end
override_append 20000, "(usermin)"
override_append 24444, "(netbeans)"
override_append 26000, "(eve-online)", 6
override_append 26900, "(eve-online)", 6
override_append 26001, "(eve-online)", 6
override_append 27010, "(half-life)"
override_append 27015, "(half-life)"
override_append 27374, "(sub7)"
override_append 31337, "(back-orifice)"

$, = '/'
$map.keys.sort.each do |port|
  if $map[port][6] != $map[port][17]
    $map[port][6].each{|x| x.sub!(/-?tcp(-\d+)?$/,'\1')}  unless $map[port][17].empty?
    $map[port][17].each{|x| x.sub!(/-?udp(-\d+)?$/,'\1')} unless $map[port][6].empty?
  end
  if $map[port][6] == $map[port][17]
    puts "#{port},*,#{$map[port][6]}"
  else
    puts "#{port},6,#{$map[port][6]}"   unless $map[port][6].empty?
    puts "#{port},17,#{$map[port][17]}" unless $map[port][17].empty?
  end
end
