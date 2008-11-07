#!/usr/bin/env ruby

$type_map = Hash.new{|h,k| h[k] = Hash.new{|h,k| h[k] = []}}

proto = { "tcp" => 6, "udp" => 17 }
while line = gets
  next if line =~ %r{^\s*(?:#|$)}
  if line =~ %r{^(\S+)\s+(\d+)/(tcp|udp)\b}
    $type_map[Integer($2)][proto[$3]] << $1.downcase unless 
    $type_map[Integer($2)][proto[$3]].include?($1.downcase)
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

$, = '/'
$type_map.keys.sort.each do |port|
  if $type_map[port][6] == $type_map[port][17]
    puts "#{port},*,#{$type_map[port][6]}"
  else
    puts "#{port},6,#{$type_map[port][6]}"   unless $type_map[port][6].empty?
    puts "#{port},17,#{$type_map[port][17]}" unless $type_map[port][17].empty?
  end
end
