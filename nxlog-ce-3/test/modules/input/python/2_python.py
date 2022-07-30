import os
import tarfile

import nxlog

LOG_DIR = 'modules/input/python/2_logdir'
POLL_INTERVAL = 30

def read_data(module):
    nxlog.log_debug('Checking for new archives')
    for file in os.listdir(LOG_DIR):
        path = os.path.join(LOG_DIR, file)
        nxlog.log_debug("Attempting to read from '{}'".format(path))
        try:
            for line in read_tar(path):
                event = module.logdata_new()
                event.set_field('ImportFile', path)
                event.set_field('raw_event', line.decode('utf-8'))
                event.post()
                nxlog.log_debug("Added event from '{}'".format(path))
            nxlog.log_debug("Added all events from '{}'".format(path))
            # Each archive should be removed after reading to prevent reading
            # the same file again. Requires adequate permissions.
            #nxlog.log_debug("Deleting file '{}'".format(path))
            #os.remove(path)
        except tarfile.ReadError:
            msg = "Skipping invalid tar file '{}'".format(path)
            nxlog.log_error(msg)
    # Check for files again after specified delay
    msg = 'Adding a read event with {} seconds delay'.format(POLL_INTERVAL)
    nxlog.log_debug(msg)
    module.set_read_timer(POLL_INTERVAL)

def read_tar(path):
    """Yield a string for each line in each file in tar file."""
    with tarfile.open(path) as tar:
        for file in tar:
            inner_file = tar.extractfile(file)
            for line in inner_file:
                yield line
