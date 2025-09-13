# This is a "retail" script where packet sniffer functionality is implemented

# This is a message to Ella.    =   =   =   =   =   =   =   =   =   =   =   =   =   =   =   =   =   =   =   =   =
# This file is where you will write all functions for the packet sniffer functionality.

# The way you will intercept packets is with a library called `scapy`. It has a function called `sniff()` that blocks the thread and calls a function you pass to argument `prn` every time a packet is intercepted, intercepted packet is passed to that function.
# So, your objective is, basically, to write that illustrous function. Use static typing so that intellisense (autocomplete) works and suggests function names.
# Note that `scapy` is not exactly a library, but rather a wrapper for a program called Npcap/libpcap (look at readme.md), so without those, you'll get errors

# What you are going to do specifically is, for each incoming packet, you will construct a dictionary object pass it in a `log()` function call. The snippet below seems complete, but
# you're going to make it look pretty and very verbose. In fact, the log entries have to be as follows:
sample_packet : dict = {
    "time": "Timestamp. Figure this out yourself, I'm too lazy lul",
    "sender": "A tuple. IP/port of the sender client. E.g. (\"127.0.0.1\",25565)",
    "receiver": "Same but IP/port of the receiving client",
    "is_outbound": "A bool. true if sender is this machine. How to figure that out? Figure it out yourself, I'm too lazy lul.",
    "location": "Geopolitical location of the other machine. There are libraries out there that will return approximate location of the machine down to the city",
    "reverse_dns_lookup": "Website of the other machine. E.g. if IP of the other machine is 74.125.68.138, this field should be set to google.com",
    "port_owner": "PID of the process that has opened the port over which the packet was sent/received.",
    "content": "Try to write the payload content here. This might be _difficult_ but good luck anyways :D"
}

# This is the most basic snippet. vvvvvvvvvvvvvvvvvvvv
import scapy # The actual library
from scapy.all import sniff # Function sniff()
from scapy.packet import Packet # Class Packet
from playground import add_to_log as log # This is a function that writes a packet to the log. It's a function I wrote and it's in playground.py right now


# This function gets called every time sniff() detects a packet. You pass its name to argument `prn` in sniff(). And yes, the name sounds funny, but it probably stands for "Packet ReturN" or whatever
# 99% of your work will be concentrated on this function
def test(pkt : Packet): # pkt : Packet - static typing. By specifying type of parameter `pkt`, IntelliSense will give you relevant autocomplete functions so that you don't have to use docs too much.
    print(pkt.summary()) # Basic information such as direction (sender IP/port, receiver IP/port)
    print(pkt.json()) # More information + actual payload.
    print() # BLank space to tell entries apart easier

    # Putting packet in the log...
    log({
        "content": pkt.summary()
        # ...
    })

# This function will start a loop in which it will keep calling whatever function you passed to `prn` every time you receive/send a package
sniff(prn=test) # Final cutoff.

# Nothing here will run befcause of sniff blocking the thread
print("HELP I CANT RUN SNIFF BLOCKED THE THREAD! :'(")