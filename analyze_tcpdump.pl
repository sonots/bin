#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use Pod::Usage;
use Time::Piece ();

our $VERSION = 0.9;

my ($inbound, $outbound, $file, $src_ip, $print_all, $is_help, $is_man);
GetOptions(
    "inbound|in"   => \$inbound,
    "outbound|out" => \$outbound,
    "file|f=s"     => \$file,
    "src-ip|ip=s"  => \$src_ip,
    "all|a"        => \$print_all,
    "help"         => \$is_help,
    "man"          => \$is_man,
);
pod2usage(1) if ($is_help);
pod2usage( -verbose => 2 ) if ($is_man);

validate_args($inbound, $outbound, $file, $src_ip);
run(is_outbound($inbound, $outbound), $file, $src_ip);

sub validate_args {
    my ($inbound, $outbound, $file, $src_ip) = @_;
    my $invalid_msg = q/invalid option value [%s]/;
    die("duplicate orientation") if (defined($inbound) && defined($outbound));
    die("no orientation") unless (defined($inbound) || defined($outbound));
    die("use option -f -ip") unless (defined($file) && defined($src_ip));
    die(sprintf(q/%s is not found/, $file)) unless (-f $file);
}

sub is_outbound {
    my ($inbound, $outbound) = @_;
    return 0 if ($inbound);
    return 1; #default: true
}

sub run {
    my ($is_outbound, $file, $src_ip) = @_;
    my $sorted_by_socket  = load_n_sort_by_socket($file, $src_ip, $is_outbound);
    my $sorted_by_session = sort_by_session($sorted_by_socket, $is_outbound);
    analyze_dump($sorted_by_session);
}

sub load_n_sort_by_socket {
    my ($file, $src_ip, $is_outbound) = @_;
    open(my $fh, '<', $file) or die qq/Cannot open "$file": $!/;
    my %hash;
    while (my $line = <$fh>) {
        push_group(\%hash, $line, $src_ip, $is_outbound);
    }
    close($fh) or die qq/Cannot close "$file": $!/;
    return \%hash;
}

#convert hash from by socket to by session
sub sort_by_session {
    my ($hash, $is_outbound) = @_;
    my %new_hash;
    my $new_key;
    for my $key (keys(%$hash)) {
        my $socket = $hash->{$key};
        for (my $count = 0; $count < @$socket; $count++) {
            if (is_new_session($socket, $count, $key, $is_outbound)) {
                $new_key = $key.":".$count;
            }
            if (!defined($new_key) || index($new_key, $key) == -1) {
                $new_key = $key.":".$count;
            }
            my $sessions = get_hash_value(\%new_hash, $new_key);
            push(@$sessions, $socket->[$count]);
            $new_hash{$new_key} = $sessions;
        }
    }
    return \%new_hash;
}

sub analyze_dump {
    my ($dump) = @_;
    my $all_cnt = 0;
    my $bad_cnt = 0;
    my $slow_cnt = 0;
    foreach my $key (keys(%$dump)) {
        my $lines = $dump->{$key};
        my @src_sock = split(/:/, $key);
        if (is_bad_session($lines, $src_sock[0])) {
            print "== bad session $key ===================\n";
            print_session($lines);
            print "\n";
            $bad_cnt++;
        } elsif (is_slow_session($lines)) {
            print "== slow session $key ==================\n";
            print_session($lines);
            print "\n";
            $slow_cnt++;
        } elsif ($print_all) {
            print "== normal session $key ==================\n";
            print_session($lines);
            print "\n";
        }
        $all_cnt++;
    }
    print "TCP session summary: all=$all_cnt, bad=$bad_cnt, slow=$slow_cnt\n";
}

sub print_session {
    my $lines = shift;
    foreach my $line (@$lines) {
        print $line."\n";
    }
}

sub is_slow_session {
    my $flow = shift;
    my @first = split(/ /, $flow->[0]);
    my @last  = split(/ /, $flow->[-1]);

    my $start = Time::Piece->strptime(substr($first[0], 0, 8), '%T');
    my $end   = Time::Piece->strptime(substr($last[0], 0, 8), '%T');
    my $msec = (substr($last[0], 9, 6) - substr($first[0], 9, 6)) / 1000000;
    my $time = $end - $start + $msec;
    return ($time >= 3.0);
}

sub is_bad_session {
    my ($lines, $src_sock) = @_;
    for (my $count = 0; $count < @$lines; $count++) {
        my @first = split(/ /, $lines->[$count]);
        if ($first[2] ne $src_sock || index($first[5], "S") == -1) {
            next;
        }
        ($lines->[$count + 1]) or next;
        my @second = split(/ /, $lines->[$count + 1]);
        if ($second[4] eq $src_sock.":" && index($second[5], "S") != -1) {
            next;
        }
        return 1; #problem
    }
    return 0; #no problem
}

sub push_group {
    my ($hash, $line, $src_ip, $is_outbound) = @_;
    chomp($line);
    return $hash unless ($line);
    my $key = decide_key($line, $src_ip, $is_outbound);
    my $group = get_hash_value($hash, $key);
    push(@$group, $line);
    $hash->{$key} = $group;
    return $hash;
}

sub get_hash_value {
    my ($hash, $key) = @_;
    unless (exists($hash->{$key})) {
        my @lines = ();
        $hash->{$key} = \@lines;
    }
    return $hash->{$key};
}

sub decide_key {
    my ($line, $src_ip, $is_outbound) = @_;
    my @column = split(/ /, $line);
    if (index($column[2], $src_ip.".") != -1) {
        if ($is_outbound) {
            return $column[2];
        } else {
            chop($column[4]);
            return $column[4];
        }
    } elsif (index($column[4], $src_ip.".") != -1) {
        if ($is_outbound) {
            chop($column[4]);
            return $column[4];
        } else {
            return $column[2];
        }
    } else {
        print "[info] ignore line: ".$line."\n";
        return "nogroup";
    }
}

sub is_new_session {
    my ($socket, $count, $key, $is_outbound) = @_;

    my @columns = split(/ /, $socket->[$count]);
    #not SYN
    return 0 if (index($columns[5], "S") == -1);
    #check key(outbound: local_port, inbound: local_port of src)
    return 0 if ($columns[4] eq $key.":");
    #previous is SYN > not new session
    ($socket->[$count - 1]) or return 0;
    my @before = split(/\s/, $socket->[$count - 1]);
    if (index($before[5], "S") != -1) {
        return 0;
    }
    return 1; #new session
}

__END__

=head1 NAME

B<analyze_tcpdump.pl> - tcpdumpをイイ感じに解析する

=head1 VERSION

0.9

=head1 SYNOPSIS

  Options:
    --inbound|-in     analyze orientation(Either in or out is must)
    --outbound|-out   analyze orientation(Either in or out is must)
    --file|-f         target file(must)
    --src-ip|-ip      target src ip(must)
    --all|-a          print all sessions (including normal sessions)
    --help|-h         print brief help message(and exit)
    --man             print full documentaion(and exit)

=head1 OPTIONS

=over 4

=item B<--inbound|-in>

analyze orientation is inbound(Either in or out is must)

=item B<--outbound|-out>

analyze orientation is outbound(Either in or out is must)

=item B<--file|-f>

Set target dump file(must)

=item B<--src-ip|-ip>

Set target src_ip(must)

=item B<--help>

Print brief help message and exit

=item B<--man>

Prints the manual page and exit

=back

=head1 DESCRIPTION

This is tcpdump analyzer

=head1 AUTHOR

=cut

# Local Variables:
# mode: perl
# perl-indent-level: 4
# indent-tabs-mode: nil
# coding: utf-8-unix
# End:
#
# vim: expandtab shiftwidth=4:

