#!/usr/bin/env ruby

$map = Hash.new{|h,k| h[k] = Hash.new{|h,k| h[k] = []}}

while line = gets
  break if line =~ %r{^(-+\s+-+)\s}
end
size = $1.length

while line = gets
  next unless line[0...size] =~ %r{^(\d+)\s+(\S(?:.*\S)?)\s*$}
  $map[Integer($1)] = $2
end

$map[61]  = "(host internal)"
$map[63]  = "(local network)"
$map[68]  = "(distributed fs)"
$map[99]  = "(encryption)"
$map[114] = "(0-hop)"
$map[253] = "(experimental)"
$map[254] = "(experimental)"

$map.keys.sort.each do |proto|
  puts "#{proto},#{$map[proto]}"
end
