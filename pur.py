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
piece_length = torrent['info']['piece length'] #8388608
pieces_hash = torrent['info']['pieces']
peers_pieces = []

total_pieces = len(torrent['info']['pieces'])//20 # 2622

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
    if response and len(response) > 20:
        extra_bytes = len(response) - 20
        address_length = extra_bytes // 6
        addresses = []
        for offset in range(0, address_length):
            ip = format(ipaddress.IPv4Address(response[20 + (6 * offset) : 24 + (6 * offset)]))
            port = unpack('>H', response[24 + (6 * offset) : 24 + (6 * offset) + 2])[0]
            addresses.append((ip, port))
        return addresses
    return []
     

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
        peer_socket.settimeout(1)
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
#        print('response size {}'.format(len(response)))
        if response and len(response) == 68:
            peer_manager(peer_socket)
            peers_pieces.append((peer_socket))
        if response and len(response) > 68:
#            parsed_response = {
#                'pstrlen': unpack('>B', response[:1]),
#                'pstr': unpack('19s', response[1:20]),
#                'reserved': unpack('8s', response[20:28]),
#                'info_hash': unpack('20s', response[28:48])[0].hex(),
#                'peer_id': unpack('20s', response[48:68])
#            }
            peer_manager(peer_socket, response[68:])


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
        # process bitfield
        if parsed_message['message_id'] == 5:
            len_bitfield = parsed_message['length'] - 1
            bits = BitArray(message[5:len_bitfield+5])
            have_pieces = bits.count('1')
            peers_pieces.append([sock, sock.getpeername(), have_pieces, bits])


def peer_send_interested():
    for peer in peers_pieces:
        sock = peer[0]
        message = pack('>IB', 1, 2)
        try:
            sock.send(message)
        except OSError as err:
            print(err)
            continue
        response = b''
        try:
            while True:
                buff = sock.recv(4096)
                if not buff:
                    break
                response += buff
        except socket.timeout:
            pass
        except OSError as err:
            print(err)
            pass
        if response and len(response) >= 5:
            parsed_response = {
                'length': unpack('>I', response[:4])[0],
                'message_id': response[4]
            }
            if parsed_response['message_id'] == 1:
                peer.append(True)


def peer_having_piece(piece_index, match=1):
    count = 0
    for peer in peers_pieces:
        if int(peer[3][piece_index]) == 1 and len(peer) >= 5 and peer[4]:
            count += 1
            if count == match:
                return peer


def piece_manager():
    having_pieces = [0] * total_pieces
    block_size = 16384
    for index, piece in enumerate(having_pieces):
        if piece:
            continue
        match = 1
        piece_data = b''
        while True:
            piece_offset = 0
            peer = peer_having_piece(index, match)
            if not peer:
                break
            match += 1
            sock = peer[0]
            print('sending request to {} for piece {}'.format(peer[1], index))
            while piece_offset < piece_length:
                message_request = pack('>IBIII', 13, 6, index, piece_offset, block_size)
                try:
                    sock.send(message_request)
                except OSError as err:
                    print(err)
                    break
                print('current piece offset: {}'.format(piece_offset))
                response = b'' # size: 16397
                sock.settimeout(2)
                try:
                    while len(response) < 16397:
                        buff = sock.recv(4096)
                       # if not buff:
                       #     break
                        response += buff
                except socket.timeout:
                    pass
                except OSError as err:
                    print(err)
                    break
                if len(response) < 16397:
                    break
                parsed_response = {
                    'index': unpack('>I', response[:4])[0],
                    'id': response[4],
                    'block': response[5:block_size+5]
                }
                piece_data += parsed_response['block']
                piece_offset += block_size
            print('piece size: {}'.format(len(piece_data)))
            piece_hash = hashlib.sha1(piece_data).digest()
            expected_hash = get_piece_hash(index)
            if piece_hash == expected_hash:
                print('hash checks out')
            else:
                print('invalid piece')
                print('expected: {}'.format(expected_hash.hex()))
                print('got: {}'.format(piece_hash.hex()))


def get_piece_hash(piece_index):
    return pieces_hash[piece_index*20:piece_index*20+20]


peers = tracker_connect_udp()
peers_connect(peers)
peers_pieces = sorted(peers_pieces, key=lambda entry: entry[2] if entry[2] else 0, reverse=True)
peer_send_interested()
piece_manager()
