#!/usr/bin/env python3
"""Apply explicit reviewed conflict choices and retain the exact choices."""
import hashlib
import json
import re
import sys
from inventory import HERE, LINUX

records = json.loads(open(sys.argv[1]).read())
logpath = HERE/'evidence/conflict-decisions.json'
log = json.loads(logpath.read_text()) if logpath.exists() else []
for record in records:
    p = LINUX / record['path']
    s = p.read_text()
    pattern = r'^<<<<<<< .*?\n(.*?)^=======\n(.*?)^>>>>>>> .*?\n'
    matches = list(re.finditer(pattern, s, re.M|re.S))
    assert len(matches) == len(record['choices']), (p,len(matches),len(record['choices']))
    record['input_sha256'] = hashlib.sha256(s.encode()).hexdigest()
    for match, choice in reversed(list(zip(matches, record['choices']))):
        if choice == 'lts': replacement = match[1]
        elif choice == 'ack': replacement = match[2]
        elif choice == 'both': replacement = match[1] + match[2]
        elif isinstance(choice, dict): replacement = choice['text']
        else: raise ValueError(choice)
        s = s[:match.start()] + replacement + s[match.end():]
    p.write_text(s)
    record['output_sha256'] = hashlib.sha256(s.encode()).hexdigest()
    log.append(record)
logpath.write_text(json.dumps(log,indent=2)+'\n')
print('Resolved',len(records),'files,',sum(len(r['choices']) for r in records),'conflicts')
