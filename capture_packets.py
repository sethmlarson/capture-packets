"""User-friendly packet captures"""

import tempfile
import contextlib
import subprocess
import tempfile
import tarfile
import os
import time
from collections import namedtuple


__version__ = "0.1.0"
__all__ = ["capture_packets", "CapturePackets"]


CapturePackets = namedtuple(
    "CapturePackets", ["keylog_filename", "packet_capture", "output"]
)


@contextlib.contextmanager
def capture_packets() -> CapturePackets:
    """Runs dumpcap in the background while network activity happens"""

    # Figure out which interfaces we're going to listen to.
    # Default is to listen to them all, but if we see 'any'
    # then we stick with that since it covers them all.
    interfaces = [
        line.split(" ")[1]
        for line in subprocess.check_output(
            "dumpcap -D", shell=True, stderr=subprocess.DEVNULL
        )
        .decode()
        .split("\n")
        if line.strip()
    ]
    if "any" in interfaces:
        interfaces = ["any"]

    # Create the temporary results directory
    tmp = tempfile.mkdtemp()
    pcap_path = os.path.join(tmp, "packets.pcapng")

    # Set the keylog_filename via environment variable
    keylog_filename = os.path.join(tmp, "keylog-filename.txt")
    os.environ["SSLKEYLOGFILE"] = keylog_filename
    open(keylog_filename, "w").close()  # Touch the file!

    # Create the tarball
    output_path = os.path.join(tmp, "captured-packets.tar")
    with tarfile.open(output_path, mode="w") as output_tar, open(
        pcap_path, "w"
    ) as pcap_fd:

        # Let the packet dumping, commence!
        popen = subprocess.Popen(
            f"dumpcap {' '.join('-i ' + intf for intf in interfaces)} -w -",
            shell=True,
            stdout=pcap_fd,
            stderr=subprocess.DEVNULL,
        )

        # Wait for time to pass or for packets to start being dumped.
        start = time.time()
        while time.time() - start < 3 and os.stat(pcap_path).st_size == 0:
            time.sleep(0.1)

        try:
            yield CapturePackets(
                keylog_filename=keylog_filename,
                packet_capture=pcap_path,
                output=output_path,
            )
        finally:
            # Clean up the subprocess
            popen.terminate()
            popen.wait()

            # Add all the files to the tarball
            for path in (keylog_filename, pcap_path):
                output_tar.add(path, os.path.basename(path))
                os.remove(path)

            print(f"Captured packets available at: {output_tar!r}")
