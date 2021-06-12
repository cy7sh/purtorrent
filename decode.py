#!/usr/bin/env python3
from bcoding import bdecode

torrent_file = 'ref.torrent'

# getting the dictionary in .torrent file
with open(torrent_file, 'rb') as f:
    torrent = bdecode(f)

# debug
print('announce: '+torrent['announce'])
print(torrent['announce-list'])

# keys in torrent: ['announce', 'announce-list', 'comment', 'created by', 'creation date', 'info']
# keys in torrent['info']: ['files', 'name', 'piece length', 'pieces']
