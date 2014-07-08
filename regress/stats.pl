#!/usr/bin/perl
#	$OpenBSD$

# Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings;
use Data::Dumper;

my @files = glob("args-*.pl");

my $time_file = "time.log";
my $local_addr = undef;
my $remote_addr = undef;
my $remote_ssh = undef;
my $sudo = "sudo";
my $num_loops = 100;
my %results = ();

sub run_args($$$$)
{
	my $res = shift;
	my $file = shift;
	my $mode = shift;
	my $log = shift;

	print STDERR $file." ".$mode."\n";

	if (defined($remote_ssh)) {
		system("ssh -t $remote_ssh $sudo true")
		    or die("ssh $remote_ssh");
		system("$sudo perl remote.pl $mode ".
		    "$local_addr $remote_addr $remote_ssh $file");
	} else {
		system("$sudo perl relayd.pl $mode $file");
	}

	# parse last log entries
	while(<$log>) {
		if ($_ =~ /([^\s]+)\s([^\s]+)\s([^\s]+)\s([^\s]+)/ &&
		    $2 eq $file && $3 eq $mode) {
			$res->{$2}->{$3}->{date} = $1;
			if (ref($res->{$2}->{$3}->{time}) ne "ARRAY") {
				@{$res->{$2}->{$3}->{time}} = ();
				$res->{$2}->{$3}->{result} = $4;
			} else {
				$res->{$2}->{$3}->{result} += $4;
			}
			push ($res->{$2}->{$3}->{time}, $4);
		}
	}
}

sub run_tests($$)
{
	my $files = shift;
	my $res = shift;
	my $log;

	# truncate time log and re-open for reading
	unlink($time_file);
	open($log, ">", $time_file);
	close($log);
	open($log, "<", $time_file);

	foreach my $file (sort @{$files}) {
		next if ($file =~ /^args-time.*/);

		run_args($res, $file, "copy", $log);
		run_args($res, $file, "splice", $log);
	}

	close($log);
}

sub print_results($$)
{
	my $files = shift;
	my $res = shift;
	my $data_file;
	my $out;

	# XXX get git branch name
	$data_file = (`git rev-parse --abbrev-ref HEAD` || "relayd");
	$data_file =~ s/([^[:print:]])//g;
	$data_file .= ".data";

	print STDERR "*** results: $data_file\n";

	# print STDERR Dumper($results);

	open($out, ">", $data_file);

	foreach my $file (sort @{$files}) {
		# Skip invalid entries (config grammar test and such)
		next if (ref($res->{$file}->{copy}->{time}) ne "ARRAY");

		my $tot = $res->{$file}->{copy}->{result};
		my $all = join(" ", @{$res->{$file}->{copy}->{time}});
		print $out $file."-copy ".$tot." ".$all."\n";

		$tot = $res->{$file}->{copy}->{result};
		$all = join(" ", @{$res->{$file}->{copy}->{time}});
		print $out $file."-splice ".$tot." ".$all."\n";
	}

	close($out);
}

# XXX create SSL certificates
system("$sudo make clean; $sudo make server-cert.pem 127.0.0.1.crt");

# Now run all the tests
for (my $i = 1; $i <= $num_loops; $i++) {
	print STDERR "*** $i / $num_loops\n";
	run_tests(\@files, \%results);
}

print_results(\@files, \%results);

1;
