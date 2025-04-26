# NXLog CE Installer Script
Script created for easy compilation of the NXLog CE source package

## Note about Legacy Product
Since NXLog has released their NXLog Platform this has become a
legacy product. Nonetheless it is still as useful, reliable and
flexible as it has always been.

## Usage
Add the source package for NXLog CE to this folder, run the
script by using `./nxlog-ce.sh` and the process will begin.

There are options to `install` and `uninstall` NXLog CE through
the script, refer to the `-h` flag for more information regarding
this.

Note that since package requirement has changed from NXLog CE 2.x
this is only compatible with NXLog CE 3.x

An example `nxlog.conf` file is also made available, which
will be included in the final installation of your NXLog CE Agent.

Note that the `nxlog.conf` can be modified as needed, this
file is only intended to help you get up and running faster.

For more information on how to configure the file refer to the
documentation at `https://docs.nxlog.co/ce/current/index.html`
under the NXLog Community Edition Reference Manual.

At the time this script is compatible with Debian, Ubuntu, its
derivates, Alpine and RHEL based systems.

The compilation has worked in i386, SPARC, x86_64 and ARM based 
systems, as long as the libraries required for the compilation 
are available on your system this will go through.

## Dockerfile
A Dockerfile is provided which can be used for the purpose of
testing NXLog CE without installing it directly on the
system.
