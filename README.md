# capture-packets: User-friendly packet captures

## Please read before using

All network traffic occurring on your machine is captured (unless you specify a more specific interface, default is all interfaces). Any TLS handshakes that occur within the `capture_packets` will have their secrets dumped as well so that TLS traffic within the packet capture can be decrypted. Any TLS handshakes not occurring within the `capture_packets` context manager are unaffected. 

**Do not send this data to anyone you do not trust**. If you're using any authentication those secrets will likely be included in the packet capture. You should consider rotating your credentials after you've captured the packets to ensure there is zero chance of services being compromised. Use a secure channel (like [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole)) to distribute these files.

Any maintainers who receives files from this utility **should delete them as soon as possible** after completing the requiring task.

## Installing and instructions

To use this library you must have the `dumpcap` utility from tshark installed. [Learn how to install dumpcap](https://tshark.dev/setup/install).

Now we install the Python package from PyPI:

```bash
$ python -m pip install capture-packets
```

After that's installed we create a script and place the problematic code
within the `capture_packets` context manager:

```python
from capture_packets import capture_packets

# Wrap *all* of your networking code
# in the capture_packets() context manager:
with capture_packets() as pcap:

    # You put the code that you want to capture below here:
    import urllib3
    http = urllib3.PoolManager()
    http.request("GET", "https://service-that-is-not.working")

    # By the way, it's okay if an error happens in here. The
    # context manager still works and outputs the paths to stdout.
```

If you run the above script you'll get the following output after a few seconds:

```
Waiting for packet capture to start...
Capturing packets...
Stopping dumpcap...
Captured packets available at: /tmp/tmpcaxb58kt/captured-packets.tar
```

Once you see the last message your packets have been captured and are stored at the displayed path (in the above example, at `/tmp/tmpcaxb58kt/captured-packets.tar`). You can send the tarball to the maintainer requesting packets.

**IMPORTANT:** Make sure that all of your code is enclosed within the `capture_packets()` context manager.
Otherwise a crucial setup step to configure TLS secrets may be missed:

```python
import urllib3

# === DON'T DO THIS ===

# This won't work because TLS will get
# configured outside the context manager.
http = urllib3.HTTPSConnectionPool("service-that-is-not.working", 443)

with capture_packets():
    http.request("GET", "/")

# === DO THIS INSTEAD ===
with capture_packets():
    # TLS is configured within capture_packets() block :tada:
    http = urllib3.HTTPSConnectionPool("service-that-is-not.working", 443)
    http.request("GET", "/")
```

## Why is this useful?

There are networking issues that are impossible to debug without a packet capture and it's typically a difficult task for users to capture packets and TLS secrets themselves. This library is an attempt to make packet captures as simple as possible for users while still being comprehensive.

## What libraries are supported?

If TLS isn't being used, then in theory any networking library will work.

If TLS is being used then the library must support the `SSLKEYLOGFILE` environment variable to have TLS secrets dumped automatically as well. To name a few, urllib3, Requests, and any libraries that use those two libraries for HTTP will work with TLS.

## License

MIT
