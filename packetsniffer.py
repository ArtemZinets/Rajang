from scapy.all import sniff
from scapy.packet import Packet
from playground import add_to_log as log # This is a function that writes a packet to the log. It's a function I wrote and it's in playground.py right now
from datetime import datetime


def geolocate_ip(ip : str):
    """
    Uses a geolocation library to provide the country and city where the IP might be located.

    Args:
        ip (str): IP address we're looking up
    Returns:
        str: Country (and city?) where the machine might be located
    """


def reverse_DNS_lookup(ip : str):
    """
    Uses a reverse DNS lookup library to tell if there is a URL address associated with the given IP.

    Args:
        ip (str): You won't believe it...
    Returns:
        str: URL associated with IP (e.g. if IP is 70.12.34.56, return is "google.com")
    """


def write_intercepted_packet_to_log(intercepted_packet : Packet):
    """
    Writes information about the intercepted packet to the Log.

    Args:
        intercepted_packet (scapy.packet.Packet): Packet object of the intercepted packet.
    Returns:
        None
    """

    # "instance data"
    timestamp = intercepted_packet.time
    protocol : str

    source_ip : str = intercepted_packet["IP"].src
    destination_ip : str = intercepted_packet["IP"].dst
    source_port : int
    destination_port : int

    direction : str = "Inbound"

    # Get the protocol that the packet was sent with (TCP/UDP) and get a port from that.
    if intercepted_packet.haslayer("TCP"):
        protocol = "TCP"
        source_port = intercepted_packet["TCP"].sport
        destination_port = intercepted_packet["TCP"].dport
    elif intercepted_packet.haslayer("UDP"):
        protocol = "UDP"
        source_port = intercepted_packet["UDP"].sport
        destination_port = intercepted_packet["UDP"].dport
    
    # We assume that the packet is inbound but this check will check if it's actually outgoing
    if source_ip.split(".")[0] == source_ip.split(".")[1] and (source_ip.split(".")[0] == "10" or source_ip.split(".")[0] == "127" or source_ip.split(".")[0] == "255"):
        direction = "Outgoing"
        if destination_ip.split(".")[0] == destination_ip.split(".")[1] and (destination_ip.split(".")[0] == "10" or destination_ip.split(".")[0] == "127" or destination_ip.split(".")[0] == "255"):
            direction = "Local"

    # Put everything in the log
    log({
        "timestamp": str(datetime.fromtimestamp(intercepted_packet.time)), # type: ignore
        "protocol": protocol,
        "origin": (source_ip,source_port),
        "destination": (destination_ip,destination_port),
        "direction": direction,
        "geolocation": geolocate_ip(source_ip),
        "url_lookup": reverse_DNS_lookup(source_ip)
    })


sniff(prn=write_intercepted_packet_to_log)