#!/usr/bin/env perl

use Socket q[inet_ntoa];

$/ = \18;
while (<>) {
  my ($id,$sec,$usec,$ival,$size) = unpack 'NNNNn', $_;
  my $time = $sec + $usec * 1e-6;
  $ival = ($ival == 0xffff) ? "" : sprintf "%.6f", $ival * 1e-6;
  printf "%u,%.6f,%s,%u\n", $id, $time, $ival, $size;
}
