#!/usr/bin/python

import sys
import json
import base64
import binascii

for line in sys.stdin:
	layers = json.loads(line)
	for layer in layers:
		if layer['LayerName'] != 'Payload':
			layer = layer['Layer']
		else:
			if 'Layer' in layer:
				if layer['Layer'] != None:
					layer['Layer'] = binascii.hexlify(base64.b64decode(layer['Layer'])).decode('ascii')

		if 'Contents' in layer: 
			if layer['Contents'] != None:
				layer['Contents'] = binascii.hexlify(base64.b64decode(layer['Contents'])).decode('ascii')
		if 'Payload' in layer:
			if layer['Payload'] != None:
				layer['Payload'] = binascii.hexlify(base64.b64decode(layer['Payload'])).decode('ascii')

	print(json.dumps(layers, sort_keys = True))
