# -*- coding:utf-8 -*-
import json

import pandas as pd

if __name__ == '__main__':
    with open('mwe-result.json', 'r+') as f:
        results = json.loads(f.read())

        mwe_results = []
        for result in results.get('results'):
            title = result.get('mwe').get('title')
            severity = result.get('mwe').get('severity')
            for file in result.get('affected_files'):
                location = f"{file.get('filepath_relative')}(L{file.get('line_start')}-L{file.get('line_end')})"
                mwe_results.append({
                    "Title": title,
                    "Severity": severity,
                    "Location": location
                })

        df = pd.DataFrame(mwe_results)
        df.to_excel('result.xlsx', index=False)
