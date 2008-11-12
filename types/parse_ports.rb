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
    $map[port][proto] = name
  else
    $map[port][6] = name
    $map[port][17] = name
  end
end

override 0,  "spr-itunes", 6
override 42, "nameserver"
override 80, "http"

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
