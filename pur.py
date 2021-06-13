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

info_binary = bencode(torrent['info'])
info_hash = hashlib.sha1(info_binary).digest()
peer_id = '-qB4170-t-FvepUJaWBf'.encode('utf-8')

def tracker_connect_udp():
    connection_id = pack('>Q', 0x41727101980)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(4)
    action = pack('>I', 0)
    for tracker in torrent['announce-list']:
        tracker = tracker[0]
        # request for UDP trackers
        if tracker.startswith('udp'):
            parsed = urlparse(tracker)
            ip, port = socket.gethostbyname(parsed.hostname), parsed.port
            transaction_id = pack('>I', random.getrandbits(32))
            message = connection_id + action + transaction_id
            response = send_message_udp(sock, (ip, port), message, action, transaction_id, len(message))
            tracker_announce_udp(response[8:16], transaction_id, (ip, port), sock)


def tracker_announce_udp(connection_id, transaction_id, connection, sock):
    action = pack('>I', 1)
    ip_address = pack('>I', 0)
    num_want = pack('>i', -1)
    port = pack('>H', 8000)
    downloaded = pack('>Q', 0)
    left = pack('>Q', 0)
    uploaded = pack('>Q', 0)
    event = pack('>I', 3)
    key = pack('>I', 0)
    message = connection_id + action + transaction_id + info_hash + peer_id + downloaded + left + uploaded + event + ip_address + key + num_want + port
    response = send_message_udp(sock, connection, message, action, transaction_id, 20)
    parsed_response = {
        'action': unpack('>I', response[:4])[0],
        'transaction_id': unpack('>I', response[4:8])[0],
        'interval': unpack('>I', response[8:12])[0],
        'leechers': unpack('>I', response[12:16]),
        'seeders': unpack('>I', response[16:20])
#        'ip_address': unpack('>I', response[16:20]),
#        'port': unpack('>H', response[20:24]),
    }
    print(parsed_response)
 

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
    # for debugging
    parsed_response = {
        'action': unpack('>I', response[:4])[0],
        'transaction_id': unpack('>I', response[4:8])[0],
        'connection_id': unpack('>Q', response[8:16])[0]
    }
#    print(parsed_response)
    return response


tracker_connect_udp()
# debug
# print(torrent)
# keys in torrent: ['announce', 'announce-list', 'comment', 'created by', 'creation date', 'info']
# keys in torrent['info']: ['files', 'name', 'piece length', 'pieces']
