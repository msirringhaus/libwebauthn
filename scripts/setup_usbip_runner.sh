#!/bin/bash
set -e

NK_VERSION="v1.8.1"
USB_RUNNER="usbip-runner-$NK_VERSION"

# Download the binary, if it's not already present
if [ ! -e ./$USB_RUNNER ]; then
  wget https://github.com/Nitrokey/nitrokey-3-firmware/releases/download/$NK_VERSION/$USB_RUNNER
  chmod u+x $USB_RUNNER
fi

# Run the binary in the background
nohup ./$USB_RUNNER &

# Do what `make attach` does in nitrokey-3-firmware/runners/usbip/
lsmod | grep vhci-hcd || sudo modprobe vhci-hcd
sudo usbip list -r "localhost"
sudo usbip attach -r "localhost" -b "1-1"
sudo usbip attach -r "localhost" -b "1-1"
sleep 5
