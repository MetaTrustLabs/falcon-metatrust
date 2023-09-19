# -*- coding:utf-8 -*-
import json
import pandas as pd


def pretty(detectors, output_excel="result.xlsx"):
    df = pd.DataFrame(detectors)
    df.drop('elements', axis=1, inplace=True)
    df.drop('description', axis=1, inplace=True)
    df.drop('markdown', axis=1, inplace=True)
    df.drop('id', axis=1, inplace=True)
    df.rename(
        columns={'check': '规则', 'impact': '严重程度', 'confidence': '准确程度', 'first_markdown_element': '代码位置'},
        inplace=True)
    df = df[['规则', '严重程度', '准确程度', '代码位置']]
    df.to_excel(output_excel, index=False)
    df.to_csv(output_excel + ".csv", index=False)


def runForCompoundCase(output_excel):
    import os
    result_dir = "./test-projects/contracts/result"
    result_files = os.listdir(result_dir)
    detectors = []
    for result_file in result_files:
        result = json.load(open(os.path.join(result_dir, result_file)))
        try:
            detectors.extend(result.get("results").get("detectors"))
        except:
            pass
    pretty(detectors=detectors, output_excel=output_excel)


runForCompoundCase(output_excel="./test-projects/contracts/cyptex-result.xlsx")
