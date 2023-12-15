
#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

SRCDIR=$1
INSTALLDIR=$2

$(dirname "$0")/install_openssl.sh $SRCDIR $INSTALLDIR
