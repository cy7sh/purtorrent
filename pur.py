#!/usr/bin/env python3
from bcoding import bencode, bdecode
import hashlib

torrent_file = 'ref.torrent'

# getting the dictionary in .torrent file
with open(torrent_file, 'rb') as f:
    torrent = bdecode(f)

# making tracker request
info_binary = bencode(torrent['info'])
info_hash = hashlib.sha1(info_binary).digest()
peer_id = '-qB4350-kwsSnUYwydys'

# debug
print('announce: '+torrent['announce'])
print(torrent['announce-list'])
print(info_hash)

# keys in torrent: ['announce', 'announce-list', 'comment', 'created by', 'creation date', 'info']
# keys in torrent['info']: ['files', 'name', 'piece length', 'pieces']
