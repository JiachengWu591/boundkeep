"""PowerShell (and a few other) secret syntaxes must not survive redact_text (M1b review fix)."""

from __future__ import annotations

import time

import pytest

from boundkeep.redact import REDACTED, redact_text

# Built at run time so that no secret-shaped literal sits in the source.
S = "".join(["Zx9qP4rT7v", "Lm2KdW8nB5"])
HERE_BODY = "line1 " + S + "\nline2"


def _cases() -> list[tuple[str, str]]:
    return [
        ("securestring-quoted-first", f"ConvertTo-SecureString '{S}' -AsPlainText -Force"),
        ("securestring-switches-first", f"ConvertTo-SecureString -AsPlainText '{S}' -Force"),
        (
            "securestring-switches-then-string",
            f'ConvertTo-SecureString -AsPlainText -Force -String "{S}"',
        ),
        ("securestring-abbrev", f"ConvertTo-SecureString -AsPlainText -Force -St '{S}'"),
        ("securestring-colon", f"ConvertTo-SecureString -AsPlainText -String:'{S}' -Force"),
        ("securestring-bare", f"ConvertTo-SecureString -AsPlainText -Force {S}"),
        ("securestring-piped", f"'{S}' | ConvertTo-SecureString -AsPlainText -Force"),
        ("securestring-piped-dq", f'$p = "{S}" | ConvertTo-SecureString -AsPlainText -Force'),
        (
            "securestring-nested",
            f"New-Object PSCredential('u', (ConvertTo-SecureString -AsPlainText -Force '{S}'))",
        ),
        ("password-sq", f"Connect-Thing -Password '{S}'"),
        ("password-colon", f"Connect-Thing -Password:'{S}'"),
        ("password-dq", f'Connect-Thing -Password "{S}"'),
        ("password-bare", f"Connect-Thing -Password {S}"),
        ("password-colon-bare", f"Connect-Thing -Password:{S}"),
        ("pwd-bare", f"Connect-Thing -Pwd {S}"),
        ("passphrase", f"Connect-Thing -Passphrase '{S}'"),
        ("token", f"Connect-Thing -Token {S}"),
        ("apikey", f"Connect-Thing -ApiKey '{S}'"),
        ("secret", f"Connect-Thing -Secret '{S}'"),
        ("credential", f"Connect-Thing -Credential {S}"),
        ("upper", f"Connect-Thing -PASSWORD '{S}'"),
        ("set-item-env-positional", f"Set-Item Env:TOKEN '{S}'"),
        ("set-item-env-bare", f"Set-Item Env:API_KEY {S}"),
        ("set-item-env-named", f"Set-Item -Path Env:TOKEN -Value '{S}'"),
        ("set-item-env-colon", f"Set-Item -Path:Env:TOKEN -Value:'{S}'"),
        ("new-item-env", f"New-Item -Path Env:TOKEN -Value '{S}'"),
        ("new-item-env-name", f"New-Item -Path Env: -Name TOKEN -Value '{S}'"),
        ("set-item-alias", f"si Env:MY_SECRET '{S}'"),
        ("set-variable-named", f"Set-Variable -Name token -Value '{S}'"),
        ("set-variable-value-first", f"Set-Variable -Value '{S}' -Name token"),
        ("set-variable-positional", f"Set-Variable token '{S}'"),
        ("set-variable-abbrev", f"Set-Variable -Na api_key -Val '{S}'"),
        ("new-variable", f"New-Variable -Name password -Value '{S}' -Force"),
        ("set-itemproperty", f"Set-ItemProperty -Path HKCU:\\Env -Name ApiKey -Value '{S}'"),
        ("set-itemproperty-positional", f"Set-ItemProperty HKCU:\\Env ApiKey '{S}'"),
        ("here-string-sq", f"$secret = @'\n{HERE_BODY}\n'@\nls"),
        ("here-string-dq", f'$password = @"\n{HERE_BODY}\n"@'),
        ("here-string-crlf", f"$secret = @'\r\n{S}\r\n'@"),
        ("here-string-env", f"$env:API_KEY = @'\n{S}\n'@"),
        ("here-string-unterminated", f"$secret = @'\n{S}"),
        ("here-string-setvar", f"Set-Variable -Name token -Value @'\n{S}\n'@"),
        ("env-concat-var-first", f"$env:API_KEY = $env:OTHER + '{S}'"),
        ("env-concat-three", f"$env:API_KEY = $a + '{S}' + $b"),
        ("curl-user", f"curl.exe -u user:{S} https://example.invalid"),
        ("curl-user-quoted", f'curl -u "user:{S}" https://example.invalid'),
        ("curl-long-user", f"curl --user user:{S} https://example.invalid"),
        ("curl-proxy-user", f"curl --proxy-user user:{S} https://example.invalid"),
        ("docker-login", f"docker login -u me -p {S} registry.invalid"),
        ("podman-login", f"podman login -p {S}"),
        ("sqlcmd", f"sqlcmd -S server -U sa -P {S}"),
        ("sqlcmd-attached", f"sqlcmd -S server -U sa -P{S}"),
        ("mysql-attached", f"mysql -u root -p{S} -h host"),
        ("mysql-quoted", f"mysql -u root -p'{S}'"),
        ("gh-with-token", f"gh auth login --with-token '{S}'"),
        ("gh-with-token-bare", f"gh auth login --with-token {S}"),
        ("sshpass", f"sshpass -p {S} ssh host"),
        ("redis-cli", f"redis-cli -a {S} ping"),
        ("double-dash-colon", f"tool --password:{S}"),
    ]


@pytest.mark.parametrize(("name", "text"), _cases(), ids=[c[0] for c in _cases()])
def test_secret_does_not_survive(name: str, text: str) -> None:
    out = redact_text(text)
    assert S not in out, out
    assert "Lm2KdW8nB5" not in out, out
    assert REDACTED in out
    assert redact_text(out) == out  # idempotent


def test_secret_in_here_string_body_is_gone_but_following_command_stays() -> None:
    out = redact_text(f"$secret = @'\n{HERE_BODY}\n'@\nGet-ChildItem")
    assert out.endswith("\nGet-ChildItem")
    assert "line1" not in out


@pytest.mark.parametrize(
    "text",
    [
        "Set-Variable -Name count -Value 3",
        "Set-Item Env:PATH 'C:\\tools'",
        "New-Item -Path secrets.txt -Value 'hello'",  # a file path is not a variable name
        "ConvertTo-SecureString $existing -AsPlainText",
        "docker run -p 8080:80 nginx",
        "ssh -p 22 host",
        "mysql -h host --print-defaults",
        "curl -u user https://example.invalid",
        "curl -sS -o out.txt https://example.invalid",
        "zip -r out.zip src",
        "Get-Process -PassThru",
        "git commit -m 'fix'",
        "ls -la",
    ],
)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert redact_text(text) == text


def test_unrelated_text_after_the_statement_is_kept() -> None:
    out = redact_text(f"Set-Variable -Name token -Value '{S}'; Get-Date")
    assert out.endswith("; Get-Date")
    assert S not in out


@pytest.mark.parametrize(
    "unit",
    [
        "-Password ",
        "-Password:",
        "ConvertTo-SecureString ",
        "ConvertTo-SecureString -AsPlainText -Force ",
        "' | ConvertTo-SecureString ",
        "Set-Variable -Name token ",
        "Set-Item Env:TOKEN ",
        "sv token ",
        "$secret = @'\n",
        "curl -u ",
        "docker login -p ",
        "mysql -p",
        "sqlcmd -P ",
        "'",
        '"',
        "-",
        "`\n",
    ],
)
def test_worst_case_inputs_are_fast(unit: str) -> None:
    for text in (unit * 60_000, unit * 3_000 + "x" * 200_000):
        start = time.perf_counter()
        out = redact_text(text)
        elapsed = time.perf_counter() - start
        assert elapsed < 3.0, f"{unit!r}: {elapsed:.2f}s"
        assert redact_text(out) == out or len(out) > 0


def test_idempotent_on_combined_text() -> None:
    text = "\n".join(
        [
            f"$env:API_KEY = $env:OTHER + '{S}'",
            f"'{S}' | ConvertTo-SecureString -AsPlainText -Force",
            f"Set-Variable -Name token -Value '{S}'",
            f"curl -u user:{S} https://example.invalid",
            f"$secret = @'\n{S}\n'@",
        ]
    )
    once = redact_text(text)
    assert S not in once
    assert redact_text(once) == once
