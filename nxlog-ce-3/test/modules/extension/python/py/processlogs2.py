import hashlib

import nxlog

def add_checksum(event):
    # Convert field list to dictionary
    all = {}
    for field in event.field_names():
        all.update({field: event.get_field(field)})

    # Calculate checksum and add to event record
    checksum = hashlib.sha1(repr(sorted(all)).encode('utf-8')).hexdigest()
    event.set_field('ChecksumSHA1', checksum)
    nxlog.log_debug('Added checksum field')

def add_counter(event):
    # Get module object and initialize counter
    module = event.module
    if not 'counter' in module:
        module['counter'] = 0
        nxlog.log_debug('Initialized counter field')

    # Skip DEBUG messages
    severity = event.get_field('SeverityValue')
    if severity > 1:
        # Add field
        event.set_field('Counter', module['counter'])
        nxlog.log_debug('Added counter field')

        # Increment counter
        module['counter'] += 1
        nxlog.log_debug('Incremented counter')
