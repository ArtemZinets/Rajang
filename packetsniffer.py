import requests
import socket
import psutil
from scapy.all import sniff
from scapy.packet import Packet
import multiprocessing
from datetime import datetime
#   =   =   =   =   =   =   =   =   =
# Internet Activity Logging Library
# by Ella Sooley
#
# September 14, 2025
#   =   =   =   =   =   =   =   =   =

ip_dict = {
    "8.8.8.8": {
        "location": "Ashburn, United States",
        "name": "dns.google"
    }
}
entry = {}

def locate_short(ip : str):
    """
    Uses a geolocation library to provide the country and city where the IP might be located.
    -> This is a helper function for geolocate_ip
    
    Args:
        ip (str): IP address we're looking up
    Returns:
        str: Country and city where the machine might be located
    """
    response = requests.get("http://ip-api.com/json/" + ip)
    info = response.json()
    status = info.get("status")
    if status == "success":
        country = info.get("country")
        city = info.get("city")
        location = city + ", " + country
    else:
        location = info.get("message")
    return location



def lookup_short(ip : str):
    """
    Uses a reverse DNS lookup library to tell if there is a URL address associated with the given IP.
    -> This is a helper function for reverse_DNS_lookup
    
    Args:
        ip (str): You won't believe it...
    Returns:
        str: URL associated with IP
    """
    try:
        name = socket.gethostbyaddr(ip)[0]
    except socket.gaierror:
        name = "Invalid IP"
    except socket.herror:
        name = "Host error"
    return name



def geolocate_ip(ip : str):
    """
    Uses function locate_short to provide country and city of the IP, as well as add unknown IPs to the dictionary ip_dict
    
    Args:
        ip (str): IP address we're looking up
    Returns:
        str: Country and city where the machine might be located
    """
    have_ip = False
    for key in ip_dict.keys():
        if key == ip:
            have_ip = True

    if have_ip:
        _location = ip_dict.get(ip)
        assert _location is not None
        location = _location.get("location")
        
    else:
        location = locate_short(ip)
        name = lookup_short(ip)      
        ip_dict.update({ip: {"location": location, "name": name}})
        
    return location
    


def reverse_DNS_lookup(ip : str):
    """
    Uses function lookup_short to providethe URL address associated with the given IP, as well as add unknown IPs to the dictionary ip_dict
    
    Args:
        ip (str): IP of which we want to find the associated URL
    Returns:
        str: URL associated with IP (e.g. if IP is 70.12.34.56, return is "google.com")
    """

    have_ip = False
    for key in ip_dict.keys():
        if key == ip:
            have_ip = True

    if have_ip:
        _name = ip_dict.get(ip)
        assert _name is not None
        name = _name.get("name")
        
    else:
        name = lookup_short(ip)
        location = locate_short(ip) 
        ip_dict.update({ip: {"location": location, "name": name}})
        
    return name



def find_PID(src_port : int, dst_port : int, direction : str):
    """
    This SHOULD return the PID for the local port
    
    Args:
        src_port (int): The number for the source port
        dst_port (int): The number for the destination port
        direction (str): Whether the local system is receiving (Incoming) or sending (Outgoing) the packet
    Returns:
        pid: The value associated with the PID of the local port
        None: If there is no local port found, reutrn no value
    """
    conns = psutil.net_connections()
    loc_port = None
    if direction == "Incoming":
        loc_port = dst_port
    elif direction == "Outgoing":
        loc_port = src_port

    for c in conns:
        if c.laddr.port == loc_port: #type: ignore
            pid = c.pid
            return pid

    return None



def write_intercepted_packet_to_log(intercepted_packet : Packet):
    """
    Writes information about the intercepted packet to the Log.

    Args:
        intercepted_packet (scapy.packet.Packet): Packet object of the intercepted packet.
    Returns:
        None
    """
    global entry
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
    entry = {
        "timestamp": str(datetime.fromtimestamp(intercepted_packet.time)), # type: ignore
        "protocol": protocol,
        "origin": (source_ip,source_port),
        "destination": (destination_ip,destination_port),
        "direction": direction,
        "geolocation": geolocate_ip(source_ip),
        "url_lookup": reverse_DNS_lookup(source_ip),
        "pid": find_PID(source_port,destination_port,direction)
    }

def loop(stop_trigger,queue):
    while True:
        if not stop_trigger.is_set():
            sniff(prn=write_intercepted_packet_to_log,count=1)
            queue.put(entry)
        else:
            return