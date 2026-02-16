from app.services.slither_runner import parse_slither_output


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
