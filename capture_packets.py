"""User-friendly packet captures"""

from __future__ import annotations

import contextlib
import os
import subprocess
import tarfile
import tempfile
import time
import typing
from functools import lru_cache

from scapy.all import TCPSession, load_layer, sniff
from scapy.config import conf
from scapy.packet import Packet

load_layer("tls")

__version__ = "0.1.2"
__all__ = ["available_interfaces", "capture_packets", "CapturedPackets"]


class CapturedPackets:
    def __init__(self, *, pcap_filepath: str, keylog_filepath: str):
        self._pcap_filepath = pcap_filepath
        self._keylog_filepath = keylog_filepath
        self._capturing = True
        self._packets: list[Packet] | None = None

    @property
    def pcap_filepath(self) -> str:
        return self._pcap_filepath

    @property
    def keylog_filepath(self) -> str:
        return self._keylog_filepath

    def tarball(self, path: str | None = None, *, gzip: bool = True) -> str:
        """Combine all file artifacts from this packet capture into a tarball"""
        if self._capturing:
            raise RuntimeError("Can't call .packets() while actively capturing")

        if path is None:
            path = f"{tempfile.mktemp()}.tar.gz"

        tarfile_mode = "w:gz" if gzip else "w"
        with tarfile.open(path, mode=tarfile_mode) as tar:
            for filepath in (
                self.pcap_filepath,
                self.keylog_filepath,
            ):
                tar.add(filepath, arcname=os.path.basename(filepath))
        return path

    def packets(
        self, *, layers: typing.Type[Packet] | list[typing.Type[Packet]] | None = None
    ) -> list[Packet]:
        if self._capturing:
            raise RuntimeError("Can't call .packets() while actively capturing")
        if self._packets is None:
            # Configure TLS application data decryption.
            conf.tls_session_enable = True
            conf.tls_nss_filename = self.keylog_filepath

            self._packets = list(sniff(offline=self.pcap_filepath, session=TCPSession))
        packets = self._packets
        if layers is not None:
            if not isinstance(layers, list):
                layers = [layers]
            packets = [
                packet
                for packet in packets
                if any(packet.haslayer(layer) for layer in layers)
            ]
        return packets


@contextlib.contextmanager
def capture_packets(
    *,
    interfaces: list[str] | None = None,
    wait_for_packets: bool = True,
    wait_before_terminate: float = 3.0,
) -> typing.Generator[CapturedPackets, None, None]:
    """Runs dumpcap in the background while network activity happens.

    :param interfaces: List of interfaces to listen to. Defaults to all interfaces.
    :param wait_for_packets:
        If true waits for packets to show up in the packet capture before yielding
        to the code within the context manager. There is almost always network
        activity happening in the background of a machine so this is a good
        way to ensure that packet capture has started before running the desired code.
        Defaults to true.
    :param wait_before_terminate:
        Number of seconds to wait after signalling the end of packet capture
        but before terminating the dumpcap process. Sometimes packets can take
        a bit to show up in the packet capture so this is done for consistency.
    """

    # Figure out which interfaces we're going to listen to.
    # Default is to listen to them all, but if we see 'any'
    # then we stick with that since it covers them all.
    if interfaces is None:
        interfaces = _default_interfaces()

    # Create the temporary results directory
    tmp = tempfile.mkdtemp()
    pcap_path = os.path.join(tmp, "packets.pcapng")

    # Set the keylog_filename via environment variable
    keylog_filename = os.path.join(tmp, "keylog-filename.txt")
    os.environ["SSLKEYLOGFILE"] = keylog_filename
    open(keylog_filename, "w").close()  # Touch the file!

    with open(pcap_path, mode="w") as pcap_fd:

        # Let the packet dumping, commence!
        popen = subprocess.Popen(
            f"dumpcap {' '.join('-i ' + intf for intf in interfaces)} -w -",
            shell=True,
            stdout=pcap_fd,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait for time to pass or for packets to start being dumped.
            if wait_for_packets:
                start = time.time()
                while time.time() - start < 3 and os.stat(pcap_path).st_size == 0:
                    time.sleep(0.1)

            pcap = CapturedPackets(
                keylog_filepath=keylog_filename, pcap_filepath=pcap_path
            )
            yield pcap
        finally:
            # Clean up the subprocess
            time.sleep(wait_before_terminate)
            popen.terminate()
            while popen.poll() is None:
                time.sleep(0.1)

            # Mark the pcap as complete so it can be inspected.
            pcap._capturing = False


def available_interfaces() -> set[str]:
    """Gets all known interfaces from dumpcap"""
    return {
        line.split(" ")[1]
        for line in subprocess.check_output(
            "dumpcap -D", shell=True, stderr=subprocess.DEVNULL
        )
        .decode()
        .split("\n")
        if line.strip()
    }


@lru_cache(1)
def _default_interfaces() -> set[str]:
    """Helper function which calls and caches the default interfaces for a system"""
    intf = available_interfaces()
    if "any" in intf:
        return {"any"}
    return intf
