# Risk Scoring Methodology

FLENS computes an aggregate score from detected vulnerability severities.

## Severity Weights

- Critical = 10
- High = 7
- Medium = 4
- Low = 1

## Formula

For vulnerabilities $v_1 \dots v_n$ with severities $s(v_i)$:

$$
\text{calculated\_score} = \sum_{i=1}^{n} w(s(v_i))
$$

Where $w$ is the severity weight mapping above.

## Thresholds

FLENS maps the calculated score to an overall risk class:

- LOW: score < 4
- MEDIUM: 4 <= score < 10
- HIGH: 10 <= score < 20
- CRITICAL: score >= 20

## Example

If a firmware has:

- 1 High vulnerability
- 1 Medium vulnerability
- 1 Low vulnerability

Then:

$$
7 + 4 + 1 = 12
$$

Overall risk is HIGH.

## Notes

- The score is based on known vulnerability findings only.
- Severity values are normalized to FLENS severity categories.
