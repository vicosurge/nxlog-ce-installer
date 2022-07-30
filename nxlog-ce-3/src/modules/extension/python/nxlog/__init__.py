#!/usr/bin/env python
# -*- coding: utf-8 -*-

import libpynxlog

class Module:
    """Wrapper class for NXLog internal module.

    This object is initialized with xm_, im_, or om_python and remains
    until NXLog is exits.
    """

    def __init__(self, c_module):
        """Constructor called by NXLog"""
        self.c_module = c_module
        self._data = {}

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value

    def __contains__(self, key):
        return key in self._data

class InputModule(Module):
    """Wrapper class for NXLog internal module.

    This object is initialized with xm_, im_, or om_python and remains
    until NXLog is exits.
    """

    def __init__(self, c_module):
        Module.__init__(self, c_module)

    def set_read_timer(self, delay):
        """Trigger a read after specified delay (im_python only).

        delay -- time in seconds before next read
        """
        libpynxlog.set_read_timer(self.c_module, delay)

    def logdata_new(self):
        """Return a new LogData object."""
        return LogData(self, libpynxlog.logdata_new())


class OutputModule(Module):
    def __init__(self, c_module):
        Module.__init__(self, c_module)


class ExtensionModule(Module):
    def __init__(self, c_module):
        Module.__init__(self, c_module)

class LogData:
    """Class implementing an event record and corresponding methods."""

    def __init__(self, module, c_logdata):
        """Called by the Module class"""
        self.module = module
        self.c_logdata = c_logdata

    def get_field(self, name):
        """Return the value of a field."""
        return libpynxlog.get_logdata_field(self.module.c_module
                                           , self.c_logdata, name)

    def set_field(self, name, value):
        """Set a field to the specified value.

        name -- the name of the field to set
        value -- the value to set for the field
        """
        return libpynxlog.set_logdata_field(self.module.c_module
                                           , self.c_logdata
                                           , name
                                           , value)

    def __str__(self):
        return "LogData..."

    def delete_field(self, name):
        """Delete a field from the event record."""
        return libpynxlog.delete_logdata_field(self.module.c_module
                                               , self.c_logdata, name)

    def post(self):
        """Post the LogData event to NXLog for further processing."""
        if isinstance(self.module, InputModule):
            libpynxlog.post_logdata(self.module.c_module, self.c_logdata)
        else:
            log_error("Trying to post logdata from non-input module")

    def field_names(self):
        """Return a list containing all field names."""
        return libpynxlog.get_logdata_field_names(self.module.c_module
                                                  , self.c_logdata)


def log_debug(msg):
    """Send a message to the internal logger at DEBUG level."""
    libpynxlog.log_debug(msg)


def log_info(msg):
    """Send a message to the internal logger at INFO level."""
    libpynxlog.log_info(msg)


def log_warning(msg):
    """Send a message to the internal logger at WARNING level."""
    libpynxlog.log_warning(msg)


def log_error(msg):
    """Send a message to the internal logger at ERROR level."""
    libpynxlog.log_error(msg)
