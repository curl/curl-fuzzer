#!/bin/bash

# Redirect the output of this script to a test file.
printf '%s\0%s\0' "$1" "$2"
