import json
import urllib2
import sys

data = {
        'status': sys.argv[2]
}

req = urllib2.Request('http://' + sys.argv[1] + ':9000/api/cplcd')
req.add_header('Content-Type', 'application/json')

response = urllib2.urlopen(req, json.dumps(data))

print sys.argv