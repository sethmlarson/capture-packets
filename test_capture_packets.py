import urllib3
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse

from capture_packets import capture_packets


def test_http():
    with capture_packets() as pcap:
        http = urllib3.PoolManager()
        resp = http.request("GET", "http://example.com")

    dns_queries: list[DNSQR] = pcap.packets(layers=DNSQR)
    assert len(dns_queries) >= 1
    dns_qnames = set(packet[DNSQR].qname for packet in dns_queries)
    assert b"example.com." in dns_qnames

    http_requests = pcap.packets(layers=HTTPRequest)
    http_responses = pcap.packets(layers=HTTPResponse)
    assert len(http_requests) == len(http_responses) == 1

    http_request: HTTPRequest = http_requests[0][HTTPRequest]
    assert http_request.raw_packet_cache == (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Accept-Encoding: identity\r\n"
        b"User-Agent: python-urllib3/1.26.13\r\n"
        b"\r\n"
    )

    http_response: HTTPResponse = http_responses[0][HTTPResponse]
    assert int(http_response.Status_Code) == resp.status == 200


def test_failed_dns():
    with capture_packets() as pcap:
        http = urllib3.PoolManager(retries=False)
        try:
            http.request("GET", "https://service-that-is-not.working")
        except Exception:
            pass

    # At least one DNSQR response that is an NXDOMAIN error (0x3)
    dns_qr_nxdomain = [
        packet
        for packet in pcap.packets(layers=DNSQR)
        if packet[DNSQR].qname == b"service-that-is-not.working."
        and packet[DNS].rcode == 0x3
    ]
    assert len(dns_qr_nxdomain) >= 1
