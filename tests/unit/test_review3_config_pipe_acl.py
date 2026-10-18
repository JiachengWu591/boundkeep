"""``doctor``'s pipe ACL judgement with the real two-entry DACL of the daemon's pipe.

The DACL is ``D:P(A;;0x12019B;;;<user SID>)(A;;0x20000;;;OW)``: the user, plus OWNER RIGHTS with
READ_CONTROL only (it stops the owner from implicitly holding WRITE_DAC). Pure: the ACL is built by
hand, no pipe is opened.
"""

from __future__ import annotations

import pytest

from boundkeep import doctor
from boundkeep.ipc import winsec

ME = "S-1-5-21-1111111111-2222222222-3333333333-1001"
EVERYONE = "S-1-1-0"
USER_MASK = 0x0012019B


def _acl(*aces: tuple[str, int, bool], dacl_present: bool = True) -> winsec.AclInfo:
    return winsec.AclInfo(
        owner_sid=ME,
        dacl_present=dacl_present,
        dacl_protected=True,
        aces=tuple(winsec.AceInfo(sid, None, allowed, mask, False) for sid, mask, allowed in aces),
        sddl="",
    )


def test_the_real_two_entry_dacl_is_ok() -> None:
    acl = _acl((ME, USER_MASK, True), (winsec.OWNER_RIGHTS_SID, 0x20000, True))
    [check] = doctor._judge_pipe_acl(acl, ME)
    assert check.status == doctor.OK


def test_the_user_only_dacl_is_ok() -> None:
    [check] = doctor._judge_pipe_acl(_acl((ME, USER_MASK, True)), ME)
    assert check.status == doctor.OK


@pytest.mark.parametrize("mask", [0x40000, 0x20000 | 0x40000, 0x12019B, 0x1F01FF, 0x10000, 0])
def test_owner_rights_with_a_wider_mask_fails(mask: int) -> None:
    acl = _acl((ME, USER_MASK, True), (winsec.OWNER_RIGHTS_SID, mask, True))
    [check] = doctor._judge_pipe_acl(acl, ME)
    assert check.status == doctor.FAIL
    assert winsec.OWNER_RIGHTS_SID in check.detail


def test_everyone_fails_even_next_to_the_owner_rights_entry() -> None:
    acl = _acl(
        (ME, USER_MASK, True),
        (winsec.OWNER_RIGHTS_SID, 0x20000, True),
        (EVERYONE, USER_MASK, True),
    )
    [check] = doctor._judge_pipe_acl(acl, ME)
    assert check.status == doctor.FAIL
    assert EVERYONE in check.detail
    assert winsec.OWNER_RIGHTS_SID not in check.detail  # only the offender is named


def test_a_deny_entry_for_owner_rights_is_not_a_grant() -> None:
    acl = _acl((ME, USER_MASK, True), (winsec.OWNER_RIGHTS_SID, 0x40000, False))
    [check] = doctor._judge_pipe_acl(acl, ME)
    assert check.status == doctor.OK


def test_a_null_dacl_fails() -> None:
    [check] = doctor._judge_pipe_acl(_acl(dacl_present=False), ME)
    assert check.status == doctor.FAIL
