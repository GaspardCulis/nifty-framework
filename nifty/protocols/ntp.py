import struct
import datetime


def extract_transmit_timestamp(ntp_packet):
    """Given an NTP packet, extract the "transmit timestamp" field, as a
    Python datetime."""

    # The transmit timestamp is the time that the server sent its response.
    # It's stored in bytes 40-47 of the NTP packet. See:
    #   https://tools.ietf.org/html/rfc5905#page-19
    encoded_transmit_timestamp = ntp_packet[40:48]

    # The timestamp is stored in the "NTP timestamp format", which is a 32
    # byte count of whole seconds, followed by a 32 byte count of fractions of
    # a second. See:
    #   https://tools.ietf.org/html/rfc5905#page-13
    seconds, fraction = struct.unpack("!II", encoded_transmit_timestamp)

    # The timestamp is the number of seconds since January 1, 1900 (ignoring
    # leap seconds). To convert it to a datetime object, we do some simple
    # datetime arithmetic:
    base_time = datetime.datetime(1900, 1, 1)
    offset = datetime.timedelta(seconds=seconds + fraction / 2**32)
    return base_time + offset


def insert_receive_timestamp(timestamp, ntp_packet):
    # Convert back to a NTP packet.
    # Unconvert the timestamp to a 32-bit unsigned integer.
    seconds = timestamp.timestamp()
    fraction = (seconds - int(seconds)) * 2**32

    # Convert the fraction to a 32-bit unsigned integer.
    fraction = int(fraction)
    seconds = int(seconds)

    # Insert the fraction into the NTP packet.
    encoded_transmit_timestamp = struct.pack("!II", seconds, fraction)
    ntp_packet[40:48] = encoded_transmit_timestamp
    return ntp_packet
