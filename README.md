# NXLog CE Installer Script
Script created for easy compilation of the NXLog CE source package

## Usage
Add the source package for NXLog CE to this folder, run the
script by using `./nxlog-ce-installer.sh` and the process will
begin.

Note that since package requirement has changed from NXLog CE 2.x
this is only compatible with NXLog CE 3.x

An example `nxlog.conf` file is also made available, which
will be included in the final installation of your NXLog CE Agent.

Note that the `nxlog.conf` can be modified as needed, this
file is only intended to help you get up and running faster.

For more information on how to configure the file refer to the
documentation at `https://docs.nxlog.co/userguide/index.html`
under the NXLog Community Edition Reference Manual.

At the time this script is compatible with Debian, Ubuntu, its
derivates and Alpine. RHEL based systems have not been
added but will be in the future.

The compilation has worked in x86_64 and ARM based systems.
