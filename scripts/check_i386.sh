#!/bin/bash

if [[ ${ARCHITECTURE} == "i386" ]]
then
    echo "Enabling i386 packages"
    dpkg --add-architecture i386
    apt-get update
    apt-get install -y zlib1g-dev:i386
fi
