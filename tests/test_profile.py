import pytest

from nsmcp.profile import Profile, load_profile, may_use_network


def test_the_three_profiles_exist():
    assert load_profile("online") is Profile.ONLINE
    assert load_profile("afgeschermd") is Profile.SHIELDED
    assert load_profile("dienst") is Profile.SERVICE


def test_unknown_profile_is_refused_and_does_not_fall_back():
    with pytest.raises(ValueError, match="onbekend profiel"):
        load_profile("vanalles")


def test_shielded_may_never_use_the_network():
    assert may_use_network(Profile.SHIELDED) is False


def test_service_may_never_use_the_network():
    assert may_use_network(Profile.SERVICE) is False


def test_only_online_may_use_the_network():
    assert may_use_network(Profile.ONLINE) is True
