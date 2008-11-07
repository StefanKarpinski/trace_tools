#!/usr/bin/env ruby

$type_map = Hash.new{|h,k| h[k] = Hash.new{|h,k| h[k] = []}}

proto = { "tcp" => 6, "udp" => 17 }
while line = gets
  next if line =~ %r{^\s*(?:#|$)}
  if line =~ %r{^(\S+)\s+(\d+)/(tcp|udp)\b}
    desc = $1.downcase
    port = Integer($2)
    prot = proto[$3]
    $type_map[port][prot] << desc unless
    $type_map[port][prot].include?(desc)
  end
end

def override port, name, proto=nil
  if proto
    $type_map[port][proto] = name
  else
    $type_map[port][6] = $type_map[port][17] = name
  end
end

override 0,  "spr-itunes", 6
override 42, "nameserver"
override 80, "http"

def emit port
  if $type_map[port][6] == $type_map[port][17]
    puts "#{port},*,#{$type_map[port][6]}"
  else
    puts "#{port},6,#{$type_map[port][6]}"   unless $type_map[port][6].empty?
    puts "#{port},17,#{$type_map[port][17]}" unless $type_map[port][17].empty?
  end
end

$, = '/'
$type_map.keys.sort.each do |port|
  if $type_map[port][6] != $type_map[port][17]
    $type_map[port][6].each{|x| x.sub!(/-?tcp(-\d+)?$/,'\1')}  unless $type_map[port][17].empty?
    $type_map[port][17].each{|x| x.sub!(/-?udp(-\d+)?$/,'\1')} unless $type_map[port][6].empty?
  end
  if $type_map[port][6] == $type_map[port][17]
    puts "#{port},*,#{$type_map[port][6]}"
  else
    puts "#{port},6,#{$type_map[port][6]}"   unless $type_map[port][6].empty?
    puts "#{port},17,#{$type_map[port][17]}" unless $type_map[port][17].empty?
  end
end
