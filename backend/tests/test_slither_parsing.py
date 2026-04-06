from app.services.slither_runner import parse_slither_output, parse_stdout_json


def test_parse_slither_output():
    payload = {
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "External call before state update.",
                    "elements": [
                        {
                            "source_mapping": {
                                "filename_relative": "contracts/Bank.sol",
                                "start": 100,
                                "length": 12,
                            }
                        }
                    ],
                }
            ]
        }
    }

    findings = parse_slither_output(payload)
    assert len(findings) == 1
    assert findings[0].title == "reentrancy-eth"
    assert findings[0].impact == "High"
    assert findings[0].confidence == "Medium"
    assert findings[0].location == "contracts/Bank.sol:100:12"


def test_parse_stdout_json_strips_solc_select_line():
    raw = b'Switched global version to 0.4.26\n{"success": true, "results": {"detectors": []}}\n'
    p = parse_stdout_json(raw)
    assert p is not None
    assert p.get("success") is True
