#!/usr/bin/env perl
##
## takes a list of raw, compressed tcpdump traces, and spit the resulting data out
## into processed flow data files and data traces of application-level behavior of
## raw, udp or tcp types.
##

$|=1;
$SIG{CHLD} = 'IGNORE';
$IP = qr/\d+\.\d+\.\d+\.\d+/;

sub load_state {
  my ($src,$dst,$prot,$sport,$dport) = @_;
  my $state = "state/$src/$dst/${prot}_${sport}_${dport}";
  -e $state or return ($id++,0,0);
  open STATE, "<$state" or die $!;
  my ($id,$time,$seqno) = split /\s+/, <STATE>;
  close STATE;
  return ($id,$time,$seqno);
}

sub save_state {
  my ($src,$dst,$prot,$sport,$dport,$id,$time,$seqno) = @_;
  my $state = "state/$src/$dst/${prot}_${sport}_${dport}";
  -d "state/$src/$dst" or system "mkdir -p state/$src/$dst";
  open STATE, ">$state" or die $!;
  print STATE "$id $time $seqno\n";
  close STATE;
}

mkdir($dir="trace");
while (<>) {
  chomp;
  my ($bin) = m{(\d+)\.tar\.bz2$} or next;
  open TAR, "tar jxvf $_ |" or die $!;
  open FLX, "| bzip2 -9 >$dir/$bin.flx.bz2" or die $!;
  open RAW, "| bzip2 -9 >$dir/$bin.raw.bz2" or die $!;
  open TCP, "| bzip2 -9 >$dir/$bin.tcp.bz2" or die $!;
  open UDP, "| bzip2 -9 >$dir/$bin.udp.bz2" or die $!;
  sleep 2; # give tar a little headstart...
  while (<TAR>) {
    chomp;
    my ($bin,$src,$dst,$prot,$sport,$dport) =
      m{(\d+)/($IP)/($IP)/(\d+)_(\d+)_(\d+)$} or next;
    my $file = $_;
    my ($id,$time,$seqno) = load_state($src,$dst,$prot,$sport,$dport);
    print "flow [$id]: $file\n";
    print FLX "$id $src $dst $prot $sport $dport\n";
    my $fh = {6=>\*TCP,17=>\*UDP}->{$prot}||\*RAW;
    open TRACE, "bin/trace -t $time -s $seqno $file |" or die $!;
    while (<TRACE>) {
      split;
      $time = $_[0];
      $seqno = pop @_ if $prot==6;
      print $fh "$id @_\n";
    }
    close TRACE or die $!;
    unlink $file or die $!;
    save_state($src,$dst,$prot,$sport,$dport,$id,$time,$seqno);
  }
  close UDP or die $!;
  close TCP or die $!;
  close RAW or die $!;
  close FLX or die $!;
  close TAR or die $!;
  system "rm -rf flows/$bin";
}

