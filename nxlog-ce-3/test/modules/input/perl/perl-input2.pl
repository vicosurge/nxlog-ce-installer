# FindBin is for adding a path to @INC, this not needed normally
use FindBin;
use lib "$FindBin::Bin/../../../../src/modules/extension/perl";

use strict;
use warnings;

use Log::Nxlog;

my $counter;

sub read_data
{
    my $event = Log::Nxlog::logdata_new();
    $counter //= 1;
    my $line = "Input2: this is a test line ($counter) that should appear in the output";
    $counter++;
    Log::Nxlog::set_field_string($event, 'raw_event', $line);
    Log::Nxlog::add_input_data($event);
    # exit 1;
    if ( $counter <= 100 )
    {
	Log::Nxlog::set_read_timer(0);
    }
}
