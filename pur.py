#!/usr/bin/env python3

from bcoding import bencode, bdecode
import hashlib
import requests
import socket
from urllib.parse import urlparse
from struct import pack, unpack
import random
import ipaddress
from bitstring import BitArray

torrent_file = 'ref.torrent'

# getting the dictionary in .torrent file
with open(torrent_file, 'rb') as f:
    torrent = bdecode(f)

info_binary = bencode(torrent['info'])
info_hash = hashlib.sha1(info_binary).digest()
peer_id = b'-qB4170-t-FvepUJaWBf'
total_length = 0
for value in torrent['info']['files']:
   total_length += value['length']

total_pieces = len(torrent['info']['pieces'])/20

#{'announce': 'http://tracker.trackerfix.com:80/announce', 'announce-list': [['http://tracker.trackerfix.com:80/announce'], ['udp://9.rarbg.me:2780/announce'], ['udp://9.rarbg.to:2940/announce'], ['udp://tracker.slowcheetah.org:14780/announce'], ['udp://tracker.tallpenguin.org:15800/announce']], 'comment': 'Torrent downloaded from https://rarbg.to', 'created by': 'mktorrent 1.0', 'creation date': 1623571896, 'info': {'files': [{'length': 31, 'path': ['RARBG.txt']}, {'length': 138680313, 'path': ['Sample', 'Sample-TBUBSM10.mkv']}, {'length': 21853755533, 'path': ['The.Big.Ugly.2020.2160p.BluRay.x265.10bit.SDR.DTS-HD.MA.5.1-SWTYBLZ.mkv']}], 'name': 'The.Big.Ugly.2020.2160p.BluRay.x265.10bit.SDR.DTS-HD.MA.5.1-SWTYBLZ', 'piece length': 8388608, 'pieces': b'\xb6\xf63\x
def tracker_connect_udp():
    connection_id = pack('>Q', 0x41727101980)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(2)
    action = pack('>I', 0)
    peers = []
    for tracker in torrent['announce-list']:
        tracker = tracker[0]
        if not tracker.startswith('udp'):
            continue
        parsed = urlparse(tracker)
        ip, port = socket.gethostbyname(parsed.hostname), parsed.port
        transaction_id = pack('>I', random.getrandbits(32))
        message = connection_id + action + transaction_id
        print('connecting tracker {}'.format(tracker))
        response = send_message_udp(sock, (ip, port), message, action, transaction_id, len(message))
        if response:
#            parsed_response = {
#                'action': unpack('>I', response[:4])[0],
#                'transaction_id': unpack('>I', response[4:8])[0],
#                'connection_id': unpack('>Q', response[8:16])[0]
#            }
            print('announcing tracker {}'.format(tracker))
            peers += tracker_announce_udp(response[8:16], (ip, port), sock)
    peers = list(set(peers))
    print('number of peers: ' + str(len(peers)))
    return peers
 

def tracker_announce_udp(connection_id, connection, sock):
    action = pack('>I', 1)
    ip_address = pack('>I', 0)
    num_want = pack('>i', -1)
    port = pack('>H', 8000)
    downloaded = pack('>Q', 0)
    left = pack('>Q', total_length)
    uploaded = pack('>Q', 0)
    event = pack('>I', 0)
    key = pack('>I', 0)
    transaction_id = pack('>I', random.getrandbits(32))
    message = connection_id + action + transaction_id + info_hash + peer_id + downloaded + left + uploaded + event + ip_address + key + num_want + port
    response = send_message_udp(sock, connection, message, action, transaction_id, 20)
    if response:
        parsed_response = {
            'action': unpack('>I', response[:4])[0],
            'transaction_id': unpack('>I', response[4:8])[0],
            'interval': unpack('>I', response[8:12])[0],
            'leechers': unpack('>I', response[12:16])[0],
            'seeders': unpack('>I', response[16:20])[0]
        }
#        print(parsed_response)
        if len(response) > 20:
            extra_bytes = len(response) - 20
            address_length = extra_bytes // 6
            addresses = []
            for offset in range(0, address_length):
                ip = format(ipaddress.IPv4Address(response[20 + (6 * offset) : 24 + (6 * offset)]))
                port = unpack('>H', response[24 + (6 * offset) : 24 + (6 * offset) + 2])[0]
                addresses.append((ip, port))
            return addresses
     

def send_message_udp(sock, connection, message, action, transaction_id, full_size):
    sock.sendto(message, connection)
    response = b''
    try:
        while True:
            buff = sock.recv(4096)
            response += buff
    except socket.timeout:
        pass
    if len(response) < full_size:
        print('not full message')
        return
    if action != response[:4] or transaction_id != response[4:8]:
        print('action or transaction_id mismatch')
        return
    return response


def peers_connect(peers):
    for peer in peers:
        print('connecting to peer {}'.format(peer[0]))
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.settimeout(4)
        try:
            peer_socket.connect(peer)
        except OSError as err:
            print('{}'.format(err))
            continue
        # do handshake
        pstrlen = 19
        pstr = b'BitTorrent protocol'
        reserved = b'\x00' * 8
        handshake = pack(">B19s8s20s20s", pstrlen, pstr, reserved, info_hash, peer_id)
        print('handshaking')
        peer_socket.send(handshake)
        response = b''
        try:
            while True:
                buff = peer_socket.recv(4096)
                if not buff:
                    break
                response += buff
        except socket.timeout:
            pass
        except OSError as err:
            print(err)
            pass
        print('response size {}'.format(len(response)))
        if response and len(response) == 68:
            peer_manager(peer_socket)
        if response and len(response) > 68:
#            parsed_response = {
#                'pstrlen': unpack('>B', response[:1]),
#                'pstr': unpack('19s', response[1:20]),
#                'reserved': unpack('8s', response[20:28]),
#                'info_hash': unpack('20s', response[28:48])[0].hex(),
#                'peer_id': unpack('20s', response[48:68])
#            }
            peer_manager(peer_socket, response[68:])
        peer_socket.close()


def peer_manager(sock, message=None):
    state = {
        'am_choking': True,
        'am_interested': False,
        'peer_choking': True,
        'peer_interested': False
    }
    if message:
        parsed_message = {
            'length': unpack('>I', message[:4])[0],
            'message_id': message[4]
        }
        print(parsed_message)
        # process bitfield
        if parsed_message['message_id'] == 5:
            len_bitfield = parsed_message['length'] - 1
            bits = BitArray(message[5:len_bitfield+1])
#            print(len(bits.bin)) # 2592


peers = tracker_connect_udp()
peers_connect(peers)
