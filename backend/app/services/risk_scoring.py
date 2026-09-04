def calculate_risk_score(
    severity: str,
    confidence: int,
) -> int:
    severity_weights = {
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 100,
    }

    severity_score = severity_weights.get(severity.lower(), 0)

    risk_score = (severity_score * 0.6) + (confidence * 0.4)

    return round(risk_score)