# MetaTrust Detectors


## 添加Detector步骤

1、明确detector所属类别(参考falcon的detector目录)，如果不确定的，可以放在detectors根目录。

2、添加Detector，继承`falcon.detectors.abstract_detector.AbstractDetector`，实现`_detect(self)` 方法，编写具体的规则代码。

3、添加测试用例，目录存放在`tests/detectors/{detector_key}/{solidity_version}`

4、单元测试，测试代码在`tests/test_detectors.py`中。

```python
# 测试用例维护
ALL_TESTCASE = [
    Test(
        falcon.detectors.codestyle.inproper_sig_verify_func.ImproperSigVerify,
        "improper_sig_verify_func.sol",
        "0.8.0",
    ),
]
```
运行单元测试:
- 运行所有测试用例：`python tests/test_detectors.py`

- 执行单个测试用例: `python tests/test_detectors.py inproper_sig_verify`

5、代码提交前，确保`python tests/test_detectors.py`可运行。

## 测试第三方项目
`python -m falcon 待检测合约代码目录`

3、为了方便进行结果对比，提供了一个json转excel的脚本`tmp/pretty_falcon_json.py`：

4、运行示例：
> python -m falcon --filter-paths "contracts/test" /Users/zhang/code/metatrust/audit_repos/atlas/contract/syncMap/contract/sync.sol --json result.json
