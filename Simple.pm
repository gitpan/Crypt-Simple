package Crypt::Simple;
$Crypt::Simple::VERSION = '0.01';

=head1 NAME

Crypt::Simple - encrypt stuff simply

=head1 SYNOPSIS

  use Crypt::Simple "maybe put a password here";
  
  my $data = encrypt($stuff);

  my $same_stuff = decrypt($data);

=head1 DESCRIPTION

This provides a simple way to encrypt stuff.  The ciphertext is suitable for
sticking in HTTP cookies or email headers since it is base-64 encoded.

=head1 AUTHOR

Marty Pauley E<lt>marty@kasei.comE<gt>

=head1 COPYRIGHT

  Copyright (C) 2001  Kasei

  This program is free software; you can redistribute it and/or modify it
  under the terms of either:
  a) the GNU General Public License;
     either version 2 of the License, or (at your option) any later version.
  b) the Perl Artistic License.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.

=cut

use strict;
use Carp;
use Crypt::Blowfish;
use Compress::Zlib;
use MIME::Base64;
use Digest::MD5 qw(md5);

sub _chunk($) { $_[0] =~ /.{1,8}/ogs }

sub import {
	my ($class, @stuff) = @_;
	my $caller = caller;
	my $stuff = join '', @stuff;
	unless ($stuff) {
		$stuff ||= "$0:$caller";
		carp "using default encryption key";
	}
	my $cipher = Crypt::Blowfish->new(md5("$class:$stuff"));

	no strict 'refs';
	*{"${caller}::encrypt"} = sub {
		my $data = $_[0];
		my $sig = md5($data);
		my $b0 = pack('NN', 0, 0);
		my $ct = '';
		foreach my $block (_chunk($sig.compress($data))) {
			$ct .= $b0 = $cipher->encrypt($b0 ^ $block);
		}
		return encode_base64($ct, '');
	};
	*{"${caller}::decrypt"} = sub {
		my $data = decode_base64($_[0]);
		my ($sig1, $sig2, @blocks) = _chunk($data);
		my $b0 = pack('NN', 0, 0);
		my $sig = $b0 ^ $cipher->decrypt($sig1);
		$b0 = $sig1;
		$sig .= $b0 ^ $cipher->decrypt($sig2);
		$b0 = $sig2;
		my $pt = '';
		foreach my $block (@blocks) {
			$pt .= $b0 ^ $cipher->decrypt($block);
			$b0 = $block;
		}
		my $result = uncompress($pt);
		croak "message digest incorrect" unless $sig eq md5($result);
		return $result;
	};

      1;
}

1;
