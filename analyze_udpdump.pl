#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use Pod::Usage;
use Time::Piece ();

our $VERSION = 0.2;

my ($file, $src_ip, $is_help, $is_man);

GetOptions(
    "file|f=s"     => \$file,
    "src-ip|ip=s"  => \$src_ip,
    "help"         => \$is_help,
    "man"          => \$is_man,
);

pod2usage(1) if ($is_help);
pod2usage( -verbose => 2 ) if ($is_man);

run($file, $src_ip);

sub run {
    my ($file, $src_ip) = @_;
    validate($file, $src_ip);
    my $sessions = sort_session($file, $src_ip);
    my $resends  = extract_resend($sessions);
    my $one_side = extract_one_side($sessions);
    print_result($sessions, $resends, $one_side);
    #print_session($sessions);
}

sub validate {
    my ($file, $src_ip) = @_;
    unless ( defined($src_ip) ) {
        die "Not specified ip! use --src_ip|-ip option.";
    }
    unless ( defined($file) ) {
        die "Not specified file! use --file|-f option.";
    }
    unless (-f $file) {
        die( sprintf(q/%s is not found/, $file) );
    }
}

sub print_session {
    my $sessions = shift;
    while (my ($key, $session) = each(%$sessions)) {
        print "$key ========================================================================\n";
        foreach my $line (@$session) {
            print "$line\n";
        }
    }
}

sub print_result {
    my ($sessions, $resends, $one_side) = @_;
    print "UDP resend flow\n";
    while (my ($key, $session) = each(%$resends)) {
        print "$key ========================================================================\n";
        foreach my $line (@$session) {
            print "$line\n";
        }
    }
    while (my ($key, $session) = each(%$one_side)) {
        print "$key ========================================================================\n";
        foreach my $line (@$session) {
            print "$line\n";
        }
    }
    my $session_num  = scalar(keys(%$sessions));
    my $resend_num   = scalar(keys(%$resends));
    my $one_side_num = scalar(keys(%$one_side));
    print "\ntotal:".$session_num." resend:".$resend_num." one_side:".$one_side_num."\n";
}

sub extract_resend {
    my $sessions = shift;
    my %resends;
    while (my ($key, $session) = each(%$sessions)) {
        my @first = split(/ /, $session->[0]);
        my @last  = split(/ /, $session->[-1]);
        my $start = Time::Piece->strptime(substr($first[0], 0, 8), '%T');
        my $end   = Time::Piece->strptime(substr($last[0], 0, 8), '%T');
        $resends{$key} = $session if (($end - $start) >= 5);      
    }
    return \%resends;
}

sub extract_one_side {
    my $sessions = shift;
    my %one_side;
    while (my ($key, $session) = each(%$sessions)) {
        $one_side{$key} = $session if (scalar($session) == 1);
    }
    return \%one_side;
}

sub sort_session {
    my ($file, $src_ip) = @_;
    open(my $fh, '<', $file) or die qq/Cannot open "$file": $!/;
    my %buffer;
    my $src_buf = "";
    my $session_num = 0;
    while (my $line = <$fh>) {
        chomp($line);
        my @columns = split(/ /, $line); #[2] src, [4] dst
        my $src_sock;
        $src_sock = $columns[2] if (index($columns[2], $src_ip) > -1);
        if (index($columns[4], $src_ip) > -1) {
            $src_sock = $columns[4];
            $src_sock =~ s/://;
        }
        if ($src_buf eq $src_sock) {
            my $lines = $buffer{$src_sock.":".$session_num};
            push(@$lines, $line); 
        } else {
            $session_num++;
            $buffer{$src_sock.":".$session_num} = [$line];
            $src_buf = $src_sock;
        }
    }
    close($fh) or die qq/Cannot close "$file": $!/;
    return \%buffer;
}
__END__

=head1 NAME

B<analyze_udpdump.pl> - UDPのtcpdumpをイイ感じに解析する

=head1 VERSION

0.2

=head1 SYNOPSIS

  Options:
    --file|-f         target file(must)
    --src-ip|-ip      target src ip(must)
    --help|-h         print brief help message(and exit)
    --man             print full documentaion(and exit)

=head1 OPTIONS

=over 4

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

