# capture-packets: User-friendly packet captures

**It's recommended to read the below carefully before use:**

All network traffic occurring on your machine is captured (unless you specify a more specific interface, default is all interfaces).
Any TLS handshakes that occur within the `capture_packets()` context will have their secrets dumped so that TLS traffic within the packet capture can be decrypted.
Any TLS handshakes not occurring within the `capture_packets()` context are unaffected. This library uses [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html) to capture
packets so dumpcap must be installed locally to use.

The following are some examples of data captured by dumpcap:

- IP addresses
- DNS requests and responses
- TLS handshakes, SNI, decrypted application data
- HTTP requests, responses, authentication

If the data goes over the network, this library will likely capture it and make it available to whoever has access to the packet capture files.

**Do not send this data to anyone you do not trust**. **Do not make this data publicly, on GitHub, or send it over email**.
If credentials are in use, you should consider rotating your credentials after you've captured the packets to ensure there is zero chance of services being compromised.
Use a secure channel (like [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole)) to distribute these files.
Anyone who receives files from this utility **should delete them as soon as possible** after completing the requiring task to avoid accidental disclosure of information.

## User Guide

To use this library you must have the `dumpcap` utility from tshark installed. [Learn how to install dumpcap](https://tshark.dev/setup/install).

Now we install the Python package from PyPI:

```bash
$ python -m pip install capture-packets
```

After that's installed we create a script and place the code
within the `capture_packets` context manager:

```python
import urllib3
from capture_packets import capture_packets

# Wrap *all* of your networking code
# in the capture_packets() context manager:
with capture_packets() as pcap:

    # You put the code that you want to capture below here:
    http = urllib3.PoolManager()
    http.request("GET", "https://example.com")
```

That's all it takes to capture some packets. But what if our network code is raising an error? We can suppress all exceptions within the same context using [`contextlib.suppress()`](https://docs.python.org/3/library/contextlib.html#contextlib.suppress):

```python
import contextlib
from capture_packets import capture_packets

# Multiple context managers in one context!
# You can make the 'Exception' type more specific if desired.
with contextlib.suppress(Exception), capture_packets() as pcap:

    http = urllib3.PoolManager()

    # Now if this request fails then we still exit the context manager.
    http.request("GET", "https://service-that-is-not.working")
```

If we're sending them to someone else we likely want to use the `.tarball()` method:

```python
>>> print(pcap.tarball())
/tmp/tmpvuujy8s0.tar.gz
```

This will return a new tarball path containing all the data about the packet capture.
You can send this tarball to anyone who needs access to the packet capture.

### Examining packets locally

Or if you want to dissect the data locally you can use the `.packets()` method to get a list of scapy packets.
TLS packets are decrypted using the keylog file if necessary. You can read the [scapy documentation](https://scapy.readthedocs.io/en/latest/) for more information.

```python
from scapy.layers.dns import DNSQR

packets = pcap.packets(layers=DNSQR)
assert packets[0][DNSQR].qname == b"service-that-is-not.working."
```

### TLS secrets must be configured within the context manager

**IMPORTANT:** Make sure that all of your code is enclosed within the `capture_packets()` context manager.
Otherwise a crucial setup step to configure TLS secrets may be missed:

```python
import urllib3

# This won't work because TLS will get
# configured outside the context manager.
http = urllib3.HTTPSConnectionPool("service-that-is-not.working", 443)

with capture_packets():
    http.request("GET", "/")

# Instead place your HTTP connections within the context manager
# so that TLS secret dumping is configured properly.
with capture_packets():
    # TLS is configured within capture_packets() block :tada:
    http = urllib3.HTTPSConnectionPool("service-that-is-not.working", 443)
    http.request("GET", "/")
```

### Reusable script template

Below is a simple script that maintainers can give to users to gather packet capture information about an issue:

```python
# Read the User Guide for capture-packets for more info:
# https://github.com/sethmlarson/capture-packets

import contextlib
from capture_packets import capture_packets

with contextlib.suppress(Exception), capture_packets() as pcap:

    # YOUR CODE GOES HERE!

print(f"Captured packets are here: {pcap.tarball()}")
pcap.delete()
```

## Why is this useful?

There are networking issues that are impossible to debug without a packet capture, and it's typically a difficult task for users to capture packets and TLS secrets themselves. This library is an attempt to make packet captures as simple as possible for users while still being comprehensive.

## What libraries are supported?

If TLS isn't being used, then in theory any networking library will work.

If TLS is being used then the library must support the `SSLKEYLOGFILE` environment variable to have TLS secrets dumped automatically as well. To name a few, urllib3, Requests, and any libraries that use those two libraries for HTTP will work with TLS.

## License

MIT
