#!/usr/bin/perl
#
# httpd-log-anon-filter - anonymizing log filter for httpd logs
# Copyright (C) 2016,2017  Christian Garbs <mitch@cgarbs.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 

use strict;
use warnings;

use String::Random qw(random_regex random_string);
use Digest::SHA qw(sha256);


my $logfile = shift @ARGV || die  'no output file given';

open my $log_fh, '>>', $logfile or die "can't open `$logfile': $!\n";
$log_fh->autoflush();

# sha256 version with 256 bits random
# this will give a new salt on every invocation, meaning that the
# hashes are 'new' after logrotate's daily 'apache reload'
my $salt = random_string( "b" x 32 );

while (my $line = <STDIN>) {
    my ($ip, $tail) = split /\s+/, $line, 2;

    # convert salt plus hostname field contents to sha256 hash
    my $hash = sha256( $salt . $ip );
    
    if ($ip =~ /:/) {
	# host field looks like IPv6:
	# convert complete sha256 hash to an IPv6 address
	$ip = join( ':', unpack( '(H4)8', $hash));

	# generate "documentation" addresses: 2001:db8::/32
	# $ip = '2001:db8:' . join( ':', unpack( '(H4)6', $hash));

	# generate discard addresses? 0100::/64
	# $ip = '0100::' . join( ':', unpack( '(H4)4', $hash));
    }
    else {
	# host field contains IPv4, resolved hostname or any other junk:
	# convert first 4 bytes of hash to an IPv4 address
	$ip = join( '.', unpack( 'C4', $hash));

	# generate IPs in local pool (use 10.0.0.0/8 because it's the biggest local range)
	# $ip = '10.' . join( '.', unpack( 'C3', $hash));
    }
    print $log_fh "$ip $tail";
}

close $log_fh or die "can't close `$logfile': $!\n";
