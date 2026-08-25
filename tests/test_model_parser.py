import pytest

from commitgate_core import GateError, MAX_MODEL_RESPONSE_BYTES, strict_parse_verdict


@pytest.mark.parametrize("verdict", ["APPROVE", "REJECT", "INCONCLUSIVE"])
def test_exact_model_schema_accepts_only_enum(verdict):
    assert strict_parse_verdict('{"verdict":"' + verdict + '"}') == verdict
    assert strict_parse_verdict({"verdict": verdict}) == verdict


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "{}",
        '{"verdict":"APPROVE","reason":"x"}',
        '{"other":"APPROVE"}',
        '{"verdict":1}',
        '{"verdict":null}',
        '{"verdict":"YES"}',
        '{"verdict":{"value":"APPROVE"}}',
        '[{"verdict":"APPROVE"}]',
        '{"verdict":"APPROVE","verdict":"REJECT"}',
        "```json\n{\"verdict\":\"APPROVE\"}\n```",
    ],
)
def test_hostile_model_outputs_fail(raw):
    with pytest.raises(GateError, match="MODEL_ERROR"):
        strict_parse_verdict(raw)


def test_wrong_input_type_giant_response_and_model_exception_are_failures():
    for raw in (None, ["APPROVE"]):
        with pytest.raises(GateError, match="MODEL_ERROR"):
            strict_parse_verdict(raw)
    with pytest.raises(GateError, match="MODEL_ERROR"):
        strict_parse_verdict({"verdict": "APPROVE", "extra": True})
    with pytest.raises(GateError, match="MODEL_ERROR"):
        strict_parse_verdict("x" * (MAX_MODEL_RESPONSE_BYTES + 1))
