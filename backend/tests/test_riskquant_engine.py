from riskquant.engine import compute_r_comp, compute_r_dast, compute_r_sast


def test_compute_r_sast():
    assert compute_r_sast([("High", "High"), ("Low", "Medium")]) == 10 * 1.0 + 2 * 0.8
    assert compute_r_sast([("High", "Low")]) == 10 * 0.45
    assert compute_r_sast([("Critical", "High")]) == 12 * 1.0
    assert compute_r_sast([("Informational", "Medium")]) == 1 * 0.8
    assert compute_r_sast([]) == 0.0


def test_compute_r_dast():
    assert compute_r_dast([(90.0, True), (30.0, True)]) == 90.0
    assert compute_r_dast([(90.0, False)]) == 90.0 * 0.42
    assert compute_r_dast([]) == 0.0


def test_compute_r_comp():
    value = compute_r_comp(20)
    assert 45.0 < value < 55.0
