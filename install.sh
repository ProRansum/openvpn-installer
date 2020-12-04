  
#!/bin/bash
#
# https://github.com/ProRansum/openvpn-installer
#
# Copyright (c) 2020 ProRansum. Released under the MIT License.

# Set working directory 
WDIR="`dirname "$0"`";

# Initialize config variables 
source "$WDIR/configs";

# Determine OS platform 
$WDIR/os-detect.sh