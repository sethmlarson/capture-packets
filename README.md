# capture-packets: User-friendly packet captures

## Installing and instructions

To use this library you must have the `dumpcap` utility from tshark installed. [Learn how to install dumpcap](https://tshark.dev/setup/install).

Now we install the Python package from PyPI:

```
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

If you run the above script you'll get the following output:

```python

```

## What data gets captured?

All network traffic occurring on your machine is captured (unless you specify a more specific interface, default is all interfaces). Any TLS handshakes that occur within the `capture_packets` will have their secrets dumped as well so that TLS traffic within the packet capture can be decrypted. Any TLS handshakes not occurring within the `capture_packets` context manager are unaffected. 

**Do not send this data to anyone you do not trust**. If you're using any authentication those secrets will likely be included in the packet capture. You should consider rotating your credentials after you've captured the packets to ensure there is zero chance of services being compromised.

## Why is this useful?

There are networking issues that are impossible to debug without a packet capture and it's difficult to make packet captures easy for users. This library is an attempt to make packet captures as simple as possible.

## What libraries are supported?

If TLS isn't being used, then in theory any networking library will work.

If TLS is being used then the library must support the `SSLKEYLOGFILE` environment variable to have TLS secrets dumped automatically as well. To name a few, urllib3, Requests, and any libraries that use those two libraries for HTTP will work with TLS.

## License

MIT
