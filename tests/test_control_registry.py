from grc_platform.common.control_registry import get_control, load_controls


def test_loads_all_93_controls():
    controls = load_controls()
    assert len(controls) == 93


def test_themes_present():
    controls = load_controls()
    themes = {c.theme for c in controls.values()}
    assert themes == {"Organizational", "People", "Physical", "Technological"}


def test_get_known_control():
    control = get_control("A.5.15")
    assert control.title == "Access control"


def test_get_unknown_control_raises():
    try:
        get_control("A.99.99")
        assert False, "expected KeyError"
    except KeyError:
        pass
