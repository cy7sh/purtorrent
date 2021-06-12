#!/usr/bin/env python3
import bencodepy

torrent_file = 'ref.torrent'

# the dictionary in .torrent file
decoded = bencodepy.bdecode(open(torrent_file,'rb').read())
