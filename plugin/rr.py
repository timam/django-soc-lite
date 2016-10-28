import os.path
import json
import re
BASE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE,'rules.json'),'r') as f:
    data = json.load(f)

for item in data:
    print item['tags']['tag'][0]
