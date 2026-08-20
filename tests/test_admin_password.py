"""How the local administrator password is decided on every start.

Three sources, and the rules between them are the whole feature:

  * `BOOTSTRAP_ADMIN_PASSWORD` set   -> that is the password, reapplied each start
  * blank                            -> the app issues one and prints it each start
  * changed in the console           -> left alone, and cannot be displayed
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.auth.router import sync_local_admin
from app.config import Settings
from app.models import (
    PASSWORD_SOURCE_ENV,
    PASSWORD_SOURCE_GENERATED,
    PASSWORD_SOURCE_USER,
    LocalUser,
)
from app.security import hash_password, verify_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD


@pytest.fixture
def configure(monkeypatch):
    """Run sync_local_admin against a chosen BOOTSTRAP_ADMIN_PASSWORD.

    Settings are built with `_env_file=None` and injected directly rather than
    by setting environment variables, because `Settings` also reads a `.env`
    file — so a developer who has one would otherwise get different results
    from CI, and "blank" would silently mean "whatever is in my .env".
    """

    def apply(password: str | None):
        settings = Settings(
            _env_file=None,
            app_secret_key="test-key-not-used-anywhere-real-0123456789",
            bootstrap_admin_email=ADMIN_EMAIL,
            bootstrap_admin_password=password or "",
        )
        monkeypatch.setattr("app.auth.router.get_settings", lambda: settings)
        return settings

    return apply


def admin(db) -> LocalUser:
    return db.execute(
        select(LocalUser).where(LocalUser.email == ADMIN_EMAIL)
    ).scalar_one()


# --- a configured password wins ------------------------------------------------


def test_a_configured_password_is_used_on_first_run(db, configure):
    configure("ConfiguredPassword123")

    state = sync_local_admin(db)

    assert state.created is True
    assert state.source == PASSWORD_SOURCE_ENV
    # Never surfaced for logging: it is already in the operator's .env.
    assert state.password == ""
    assert verify_password("ConfiguredPassword123", admin(db).password_hash)


def test_editing_the_configured_password_takes_effect_on_restart(db, configure):
    """The .env file is declarative — this is the documented way back in."""
    configure("FirstPassword12345")
    sync_local_admin(db)

    configure("SecondPassword12345")
    state = sync_local_admin(db)

    assert state.changed is True
    assert state.source == PASSWORD_SOURCE_ENV
    db.expire_all()
    assert verify_password("SecondPassword12345", admin(db).password_hash)
    assert not verify_password("FirstPassword12345", admin(db).password_hash)


def test_an_unchanged_configured_password_is_not_rewritten(db, configure):
    configure("StablePassword12345")
    sync_local_admin(db)
    original_hash = admin(db).password_hash

    state = sync_local_admin(db)

    assert state.changed is False
    db.expire_all()
    assert admin(db).password_hash == original_hash


def test_a_configured_password_reactivates_a_disabled_account(db, configure):
    """A recovery password is no use if the account it opens is switched off."""
    configure("RecoveryPassword123")
    sync_local_admin(db)

    user = admin(db)
    user.is_active = False
    user.password_hash = hash_password("something-else-entirely")
    db.commit()

    sync_local_admin(db)

    db.expire_all()
    assert admin(db).is_active is True
    assert verify_password("RecoveryPassword123", admin(db).password_hash)


def test_a_configured_password_overrides_one_set_in_the_console(db, configure):
    """Setting it in .env is how you take the account back."""
    configure(None)
    sync_local_admin(db)
    user = admin(db)
    user.password_hash = hash_password("ChosenInTheConsole1")
    user.password_source = PASSWORD_SOURCE_USER
    db.commit()

    configure("BackFromTheEnv12345")
    state = sync_local_admin(db)

    assert state.source == PASSWORD_SOURCE_ENV
    db.expire_all()
    assert verify_password("BackFromTheEnv12345", admin(db).password_hash)


# --- blank: generated and shown every start ------------------------------------


def test_a_blank_password_is_generated_and_returned_for_display(db, configure):
    configure(None)

    state = sync_local_admin(db)

    assert state.created is True
    assert state.source == PASSWORD_SOURCE_GENERATED
    assert state.password  # the caller prints this
    assert verify_password(state.password, admin(db).password_hash)


def test_a_generated_password_is_reissued_on_every_start(db, configure):
    """The point of the feature: missing the banner costs a restart, not the account."""
    configure(None)
    first = sync_local_admin(db)

    second = sync_local_admin(db)

    assert second.created is False
    assert second.changed is True
    assert second.password
    assert second.password != first.password
    db.expire_all()
    # The password just printed is the one that actually works.
    assert verify_password(second.password, admin(db).password_hash)
    assert not verify_password(first.password, admin(db).password_hash)


def test_a_generated_password_is_never_forced_to_be_changed(db, configure):
    """Forcing a change that the next restart undoes would be pure theatre."""
    configure(None)
    sync_local_admin(db)
    assert admin(db).must_change_password is False


def test_clearing_the_configured_password_hands_control_back(db, configure):
    configure("ConfiguredThenRemoved1")
    sync_local_admin(db)

    configure(None)
    state = sync_local_admin(db)

    assert state.source == PASSWORD_SOURCE_GENERATED
    assert state.password


# --- a chosen password is left alone -------------------------------------------


def test_a_console_password_survives_a_restart(db, configure):
    configure(None)
    sync_local_admin(db)

    user = admin(db)
    user.password_hash = hash_password("IChoseThisMyself123")
    user.password_source = PASSWORD_SOURCE_USER
    db.commit()

    state = sync_local_admin(db)

    assert state.source == PASSWORD_SOURCE_USER
    assert state.password == ""
    assert state.changed is False
    db.expire_all()
    assert verify_password("IChoseThisMyself123", admin(db).password_hash)


def test_changing_your_own_password_takes_ownership(admin_client, db, configure):
    """Self-service change must stop startup reissuing the password."""
    response = admin_client.post(
        "/account/password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": "MyOwnChosenPassword1",
            "confirm_password": "MyOwnChosenPassword1",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    db.expire_all()
    assert admin(db).password_source == PASSWORD_SOURCE_USER

    configure(None)
    state = sync_local_admin(db)
    assert state.source == PASSWORD_SOURCE_USER
    db.expire_all()
    assert verify_password("MyOwnChosenPassword1", admin(db).password_hash)


def test_an_admin_reset_takes_ownership(admin_client, db, configure):
    user = admin(db)
    response = admin_client.post(
        f"/admin/users/{user.id}/password",
        data={"password": "AdminSetThisPassword1"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    db.expire_all()
    assert admin(db).password_source == PASSWORD_SOURCE_USER
    assert admin(db).must_change_password is False


def test_an_admin_reset_can_require_a_change(admin_client, db):
    user = admin(db)
    admin_client.post(
        f"/admin/users/{user.id}/password",
        data={"password": "TemporaryPassword123", "must_change": "on"},
        follow_redirects=False,
    )

    db.expire_all()
    assert admin(db).must_change_password is True


# --- upgraded databases ---------------------------------------------------------


def test_an_upgraded_row_with_a_forced_change_is_treated_as_generated(db, configure):
    """A database from before this column existed still behaves sensibly.

    `must_change_password` used to be set only for an app-generated password,
    so it is the honest thing to infer from rather than guessing.
    """
    configure(None)
    sync_local_admin(db)

    user = admin(db)
    user.password_source = ""  # what schema_sync leaves behind for an unknown
    user.must_change_password = True
    db.commit()

    state = sync_local_admin(db)
    assert state.source == PASSWORD_SOURCE_GENERATED
    assert state.password


def test_an_upgraded_row_without_a_forced_change_is_treated_as_user_owned(db, configure):
    configure(None)
    sync_local_admin(db)

    user = admin(db)
    user.password_hash = hash_password("PreexistingPassword1")
    user.password_source = ""
    user.must_change_password = False
    db.commit()

    state = sync_local_admin(db)
    assert state.source == PASSWORD_SOURCE_USER
    db.expire_all()
    assert verify_password("PreexistingPassword1", admin(db).password_hash)


def test_an_existing_admin_under_another_address_is_adopted(db, configure):
    """Don't create a second administrator alongside the one already there."""
    db.add(
        LocalUser(
            email="someone.else@example.com",
            display_name="Existing",
            password_hash=hash_password("ExistingPassword123"),
            role="admin",
            is_active=True,
            password_source=PASSWORD_SOURCE_GENERATED,
        )
    )
    db.commit()

    configure("NowConfigured12345")
    state = sync_local_admin(db)

    assert state.created is False
    assert state.email == "someone.else@example.com"
    assert len(db.execute(select(LocalUser)).scalars().all()) == 1


def test_settings_reads_a_blank_password_as_blank():
    """Guard the contract sync_local_admin depends on."""
    assert Settings(bootstrap_admin_password="").bootstrap_admin_password == ""
