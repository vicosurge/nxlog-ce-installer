# FindBin is for adding a path to @INC, this not needed normally
use FindBin;
use lib "$FindBin::Bin/../../../../src/modules/extension/perl";

use strict;
use warnings;

use Log::Nxlog;

sub write_data1
{
   my ($event) = @_;
   my $rawevt = Log::Nxlog::get_field($event, 'raw_event');
   open(OUT, '>', 'tmp/output') || die("cannot open tmp/output: $!");
   print OUT $rawevt, "(from perl)", "\n";
   close(OUT);
}
