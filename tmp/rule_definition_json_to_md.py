# -*- coding:utf-8 -*-

import json


def to_md(idx, checker, rule_json):
    return f"""
## {idx}、{checker}
**Severity**: `{rule_json.get('impact')}`

**Title**:
- {rule_json.get('wiki_title')}

**Description**:
- {rule_json.get('wiki_description')}

**Recommendation**:
- {rule_json.get('wiki_recommendation')}
"""


with open('falcon/mwe-rule-definition.json', 'r') as f:
    json_data = json.loads(f.read())

    md_summary = ''
    i = 1
    for checker, rule in json_data.items():
        md_summary += to_md(i, checker, rule)
        i += 1

    with open('mwe.md', 'w') as wf:
        wf.write(md_summary)
