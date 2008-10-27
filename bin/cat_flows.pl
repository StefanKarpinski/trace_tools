#!/usr/bin/env perl

use Socket q[inet_ntoa];

$/ = \17;
while (<>) {
  my ($id,$proto,$src,$dst,$sport,$dport) = unpack 'NUa4a4nn', $_;
  $src = inet_ntoa($src);
  $dst = inet_ntoa($dst);
  print "$id,$proto,$src,$dst,$sport,$dport\n";
}
