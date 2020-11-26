#!/bin/sh -e
#
# Helper script for the build process to apply entitlements

SRC="$1"
DST="$2"
ENTITLEMENT="$3"

rm -f "$2"
cp -a "$SRC" "$DST"
codesign --entitlements "$ENTITLEMENT" --force -s - "$DST"
