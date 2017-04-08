#! /bin/bash -e

make

SUDO=
if  [ $UID -ne 0 ]; then
    SUDO=sudo
fi

$SUDO cp latency_tracker_kmod_ceph_hist.ko /lib/modules/$(uname -r)/updates/
$SUDO depmod
$SUDO modprobe -r latency_tracker_kmod_ceph_hist
$SUDO modprobe latency_tracker_kmod_ceph_hist
