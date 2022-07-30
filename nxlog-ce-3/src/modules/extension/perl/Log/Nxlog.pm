package Log::Nxlog;

use 5.008005;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use nxlog ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);


bootstrap();


1;
__END__

=head1 NAME

NXLog - Perl module which exports some of NXLog's API to access and manipulate event data.

=head1 SYNOPSIS

  use Log::Nxlog;

=head1 DESCRIPTION

 This perl module can be used from perl code executed by NXLog's xm_perl, im_perl and om_perl module.

=head2 Methods

 The following methods are exported which can be used to manipulate the fields contained in the event data and to access NXLog's internal logging API. 
 Some of the methods are specific to im_perl and om_perl.

=over 4

=item set_field_integer(event, key, value)

 Sets the integer value in the field named 'key'.

=item set_field_string(event, key, value)

 Sets the string value in the field named 'key'.

=item set_field_boolean(event, key, value)

 Sets the boolean value in the field named 'key'.

=item get_field(event, key)

 Retreive the value associated with the field named 'key'.
 The method returns a scalar value if the key exists and the value is defined, otherwise 
 it returns undef.

=item delete_field(event, key)

 Delete the value associated with the field named 'key'.

=item field_type(event, key)

 Return a string representing the type of the value associated with the field named
 'key'. 

=item field_names(event)

 Return a list of the field names contained in the event data. Can be used to iterate over
 all the fields.

=item logdata_new()

 Returns new log event data. It should be consumed by add_input_data(), otherwise
 memory leaks could occur. Usually it is used in im_perl module.

=item add_input_data($event)

 Pushes previously created log event data into NXLog pipeline for further processing.
 Usually it is used in im_perl module.

=item set_read_timer($delay)

 Sets up a timer so that im_perl will invoke read_data after $delay seconds again.

=item log_debug(msg)

 Send the message in the argument to the internal logger on DEBUG loglevel. Does
 the same as the procedure named log_debug() in NXLog.

=item log_info(msg)

 Send the message in the argument to the internal logger on INFO loglevel. Does
 the same as the procedure named log_info() in NXLog.

=item log_warning(msg)

 Send the message in the argument to the internal logger on WARNING loglevel. Does
 the same as the procedure named log_warning() in NXLog.

=item log_error(msg)

 Send the message in the argument to the internal logger on ERROR loglevel. Does
 the same as the procedure named log_error() in NXLog.

=back


=head1 SEE ALSO

 The NXLog Reference Manual is available at http://nxlog.org
 

=head1 AUTHOR

Botond Botyanszki <botond.botyanszki@nxlog.org>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012-2016 by Botond Botyanszki

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.5 or,
at your option, any later version of Perl 5 you may have available.


=cut
