# Changelog

## 0.1.2

* Changed `capture_packets()` to return an object with references to the
  captured packets on the filesystem and parses them through `scapy` on
  demand. Previously this function would be human-facing.
* Added the `wait_for_packets` and `wait_before_terminate` parameters to control
  the reliability of the `capture_packets()` function.

## 0.1.1

* Added the `interfaces` parameter to `capture_packets()` to allow filtering 
  which interfaces that `dumpcap` would capture packets from. Default was all interfaces.

## 0.1.0

* Initial release
