#!/usr/bin/env python3
from bcoding import bencode, bdecode
import hashlib
import requests
import socket
from urllib.parse import urlparse
from struct import pack, unpack
import random

torrent_file = 'ref.torrent'

# getting the dictionary in .torrent file
with open(torrent_file, 'rb') as f:
    torrent = bdecode(f)

def tracker_request():
    info_binary = bencode(torrent['info'])
    info_hash = hashlib.sha1(info_binary).digest()
    peer_id = '-qB4170-t-FvepUJaWBf'
    params = {
            'info_hash': info_hash,
            'peer_id': peer_id,
            'uploaded': 0,
            'downloaded': 0,
            'port': 6881,
            'left': 1000000000, # todo: compute real total_size
            'event': 'started'
    }
    # socket setup for UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(2)
    for tracker in torrent['announce-list']:
        tracker = tracker[0]
        # request for UDP trackers
        if tracker.startswith('udp'):
            parsed = urlparse(tracker)
            ip, port = socket.gethostbyname(parsed.hostname), parsed.port
            connection_id = pack('>Q', 0x41727101980)
            transaction_id = pack('>I', random.getrandbits(32))
            action = pack('>I', 0)
            message = connection_id + action + transaction_id
            sock.sendto(message, (ip, port))
            response = b''
            try:
                while True:
                    buff = sock.recv(4096)
#                    if len(buff) <= 0:
#                        break
                    response += buff
            except socket.timeout:
                print('Timeout: ' + tracker)
            parsed_response = {
                action: unpack('>I', response[:4]),
                transaction_id: unpack('>I', response[4:8]),
                connection_id: unpack('>Q', response[8:16])
            }
            print(parsed_response)

tracker_request()
# debug
#print(torrent)
# keys in torrent: ['announce', 'announce-list', 'comment', 'created by', 'creation date', 'info']
# keys in torrent['info']: ['files', 'name', 'piece length', 'pieces']
