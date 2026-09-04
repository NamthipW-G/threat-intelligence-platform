from app.services.risk_scoring import calculate_risk_score


def test_high_severity_high_confidence():
    score = calculate_risk_score(
        severity="high",
        confidence=87,
    )

    assert score == 80


def test_critical_severity_full_confidence():
    score = calculate_risk_score(
        severity="critical",
        confidence=100,
    )

    assert score == 100


def test_low_severity_low_confidence():
    score = calculate_risk_score(
        severity="low",
        confidence=0,
    )

    assert score == 15