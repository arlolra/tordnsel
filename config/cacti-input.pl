#!/usr/bin/perl

# A data input script for Cacti's poller to collect TorDNSEL statistics.
# Example: ./cacti-input.pl /var/run/tordnsel/statistics.socket

use strict;
use warnings;

use IO::Socket::UNIX;

my $usage = "Usage: $0 <statistics socket>\n";

if (@ARGV != 1) {
  print STDERR $usage;
  exit 1;
}

if ($ARGV[0] eq '-h' or $ARGV[0] eq '--help') {
  print $usage;
  exit;
}

my $socket_path = shift;

my $sock = IO::Socket::UNIX->new(Peer => $socket_path)
  or die "Failed connecting to statistics socket '$socket_path': $!";

my @fields;

$/ = "\015\012";
while (<$sock>) {
  chomp;
  push @fields, join ':', split /\s+/;
}

$sock->close;

print "@fields";
