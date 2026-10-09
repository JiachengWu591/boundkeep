"""Tests for boundkeep.redact (spec section 11).

The secrets below are made up. Several are shaped like real ones on purpose (that is what the
redactor must catch) but none is valid anywhere.
"""

from __future__ import annotations

import copy
import json
import os
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boundkeep.redact import REDACTED, TRUNCATED, redact_obj, redact_text

SK_KEY = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
AWS_ID = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a1B2c3D4e5" * 4
PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"


# --------------------------------------------------------------------------------------------
# One case per pattern
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected", "secret"),
    [
        pytest.param(
            f"curl -H 'x: {SK_KEY}' https://example.invalid",
            "curl -H 'x: [REDACTED]' https://example.invalid",
            SK_KEY,
            id="sk-anthropic",
        ),
        pytest.param(
            "key sk-proj-abcdefghijklmnop_QRST-uvwx done",
            "key [REDACTED] done",
            "abcdefghijklmnop",
            id="sk-proj",
        ),
        pytest.param(
            "sk-0123456789abcdef0123",
            "[REDACTED]",
            "0123456789abcdef0123",
            id="sk-plain-at-start",
        ),
        pytest.param(
            "(sk-0123456789abcdef0123)",
            "([REDACTED])",
            "0123456789abcdef0123",
            id="sk-after-punctuation",
        ),
        pytest.param(
            f"id={AWS_ID} next",
            "id=[REDACTED] next",
            AWS_ID,
            id="aws-akia",
        ),
        pytest.param(
            "ASIAIOSFODNN7EXAMPLE",
            "[REDACTED]",
            "ASIAIOSFODNN7EXAMPLE",
            id="aws-asia",
        ),
        pytest.param(
            f"git clone https://x/{GH_TOKEN}",
            "git clone https://x/[REDACTED]",
            GH_TOKEN,
            id="github-ghp",
        ),
        pytest.param(
            "gho_"
            + "Z" * 20
            + " "
            + "ghu_"
            + "y" * 25
            + " "
            + "ghs_"
            + "9" * 22
            + " ghr_"
            + "x" * 30,
            "[REDACTED] [REDACTED] [REDACTED] [REDACTED]",
            "ZZZZZZZZZZ",
            id="github-other-prefixes",
        ),
        pytest.param(
            "token github_pat_11ABCDEFG0abcdefghij_klmnopqrstuvwxyz end",
            "token [REDACTED] end",
            "klmnopqrstuvwxyz",
            id="github-pat",
        ),
        pytest.param(
            f"x\n-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----\ny",
            "x\n[REDACTED]\ny",
            PEM_BODY,
            id="pem-rsa",
        ),
        pytest.param(
            f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----",
            "[REDACTED]",
            PEM_BODY,
            id="pem-plain",
        ),
        pytest.param(
            f"before -----BEGIN OPENSSH PRIVATE KEY-----\n{PEM_BODY}\nTRUNCATED",
            "before [REDACTED]",
            PEM_BODY,
            id="pem-missing-end-runs-to-end",
        ),
        pytest.param(
            f"a -----BEGIN PRIVATE KEY-----{PEM_BODY}-----END PRIVATE KEY----- b "
            f"-----BEGIN EC PRIVATE KEY-----\n{PEM_BODY}\n-----END EC PRIVATE KEY----- c",
            "a [REDACTED] b [REDACTED] c",
            PEM_BODY,
            id="pem-two-blocks",
        ),
        pytest.param(
            f"-----BEGIN PRIVATE KEY-----\\n{PEM_BODY}\\n-----END PRIVATE KEY-----\\n",
            "[REDACTED]\\n",
            PEM_BODY,
            id="pem-json-escaped-newlines",
        ),
        pytest.param(
            "Authorization: Bearer abcdEFGH12345.tail-part_x/y+z=",
            "Authorization: Bearer [REDACTED]",
            "abcdEFGH12345",
            id="bearer",
        ),
        pytest.param(
            "authorization: BEARER  abcdEFGH12345",
            "authorization: BEARER  [REDACTED]",
            "abcdEFGH12345",
            id="bearer-uppercase-two-spaces",
        ),
        pytest.param(
            "Authorization: Basic dXNlcjpwYXNzd29yZA==",
            "Authorization: Basic [REDACTED]",
            "dXNlcjpwYXNzd29yZA",
            id="extra-basic-auth",
        ),
        pytest.param(
            "postgres://admin:s3cr3tPw@db.internal:5432/app",
            "postgres://admin:[REDACTED]@db.internal:5432/app",
            "s3cr3tPw",
            id="extra-url-password",
        ),
        pytest.param(
            "redis://:p@ss@host:6379",
            "redis://:[REDACTED]@host:6379",
            "p@ss",
            id="extra-url-password-with-at-sign",
        ),
        pytest.param(
            "http://user:p\\w@host/",
            "http://user:[REDACTED]@host/",
            "p\\w",
            id="extra-url-password-with-backslash",
        ),
        # A key glued to Chinese prose (no spaces) or to an accented letter is still a key. The
        # "not inside an ordinary word" guard is about ASCII words ("disk-usage-report").
        pytest.param(
            f"请使用{SK_KEY}进行测试",
            "请使用[REDACTED]进行测试",
            SK_KEY,
            id="sk-between-cjk",
        ),
        pytest.param(
            f"密钥{SK_KEY}",
            "密钥[REDACTED]",
            SK_KEY,
            id="sk-after-cjk",
        ),
        pytest.param(f"café{SK_KEY}", "café[REDACTED]", SK_KEY, id="sk-after-accent"),
        pytest.param(f"π{SK_KEY}ü", "π[REDACTED]ü", SK_KEY, id="sk-between-greek-and-umlaut"),
        pytest.param(
            f"密钥{AWS_ID}后",
            "密钥[REDACTED]后",
            AWS_ID,
            id="aws-between-cjk",
        ),
        pytest.param(
            "令牌Bearer abcdEFGH12345结束",
            "令牌Bearer [REDACTED]结束",
            "abcdEFGH12345",
            id="bearer-between-cjk",
        ),
        pytest.param(
            f"x\n-----BEGIN {'X' * 100} PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----\ny",
            "x\n[REDACTED]\ny",
            PEM_BODY,
            id="pem-header-longer-than-64",
        ),
        pytest.param(
            f"-----begin private key-----\n{PEM_BODY}\n-----end private key-----",
            "[REDACTED]",
            PEM_BODY,
            id="pem-lowercase",
        ),
        pytest.param(
            f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{PEM_BODY}\n"
            "-----END PGP PRIVATE KEY BLOCK-----!",
            "[REDACTED]!",
            PEM_BODY,
            id="pem-pgp-block",
        ),
        pytest.param(
            f"-----BEGIN {'Y' * 5000} PRIVATE KEY-----{PEM_BODY}",
            "[REDACTED]",
            PEM_BODY,
            id="pem-very-long-header-unterminated",
        ),
        pytest.param(
            'curl -H "Authorization: Token abc123DEF" https://example.invalid',
            'curl -H "Authorization: [REDACTED]" https://example.invalid',
            "abc123DEF",
            id="extra-authorization-header-any-scheme",
        ),
        pytest.param(
            "authorization: hunter2plain\nnext: line",
            "authorization: [REDACTED]\nnext: line",
            "hunter2plain",
            id="extra-authorization-header-bare-value",
        ),
    ],
)
def test_token_patterns(text: str, expected: str, secret: str) -> None:
    out = redact_text(text)
    assert out == expected
    assert secret not in out


# --------------------------------------------------------------------------------------------
# One case per assignment form, including every Windows form
# --------------------------------------------------------------------------------------------

_SECRET = "hunter2-Value"

ASSIGNMENT_CASES = [
    # bash
    ("MY_API_KEY=hunter2-Value", "MY_API_KEY=[REDACTED]"),
    ("export MY_API_KEY=hunter2-Value && ls", "export MY_API_KEY=[REDACTED] && ls"),
    ('export GithubToken="hunter2-Value"', 'export GithubToken="[REDACTED]"'),
    ('export GithubToken="hunter2 Value" ; ls', 'export GithubToken="[REDACTED]" ; ls'),
    ("export db_password='hunter2 Value' x", "export db_password='[REDACTED]' x"),
    ("DB_SECRET=hunter2-Value ./run.sh", "DB_SECRET=[REDACTED] ./run.sh"),
    ("FOO_passwd=hunter2-Value", "FOO_passwd=[REDACTED]"),
    ("curl --token=hunter2-Value url", "curl --token=[REDACTED] url"),
    # PowerShell
    ('$env:API_TOKEN = "hunter2-Value"', '$env:API_TOKEN = "[REDACTED]"'),
    ('$env:API_TOKEN="hunter2-Value"', '$env:API_TOKEN="[REDACTED]"'),
    ("$env:API_TOKEN='hunter2-Value'", "$env:API_TOKEN='[REDACTED]'"),
    ("$env:API_TOKEN = 'hunter2 Value'; node x", "$env:API_TOKEN = '[REDACTED]'; node x"),
    ("$ENV:api_key = hunter2-Value", "$ENV:api_key = [REDACTED]"),
    ('${env:MY_SECRET} = "hunter2-Value"', '${env:MY_SECRET} = "[REDACTED]"'),
    ("${env:MY_SECRET}='hunter2 Value'", "${env:MY_SECRET}='[REDACTED]'"),
    # cmd
    ("set DB_PASSWORD=hunter2-Value", "set DB_PASSWORD=[REDACTED]"),
    ('set "DB_PASSWORD=hunter2 Value" && echo ok', 'set "DB_PASSWORD=[REDACTED]" && echo ok'),
    ("SET api_key=hunter2-Value", "SET api_key=[REDACTED]"),
    ("setx API_KEY hunter2-Value", "setx API_KEY [REDACTED]"),
    ('setx API_KEY "hunter2 Value"', 'setx API_KEY "[REDACTED]"'),
    ('SETX /M API_KEY "hunter2 Value"', 'SETX /M API_KEY "[REDACTED]"'),
    ('setx "API_KEY" "hunter2 Value"', 'setx "API_KEY" "[REDACTED]"'),
    # .NET
    (
        '[Environment]::SetEnvironmentVariable("API_KEY","hunter2-Value","User")',
        '[Environment]::SetEnvironmentVariable("API_KEY","[REDACTED]","User")',
    ),
    (
        "[System.Environment]::SetEnvironmentVariable('MY_TOKEN','hunter2 Value')",
        "[System.Environment]::SetEnvironmentVariable('MY_TOKEN','[REDACTED]')",
    ),
    (
        '[Environment]::SetEnvironmentVariable( "db_password" , "hunter2-Value" , "Machine" )',
        '[Environment]::SetEnvironmentVariable( "db_password" , "[REDACTED]" , "Machine" )',
    ),
    (
        '[Environment]::SetEnvironmentVariable("API_KEY",$secretValue,"User")',
        '[Environment]::SetEnvironmentVariable("API_KEY",[REDACTED],"User")',
    ),
    # JSON-like pairs
    ('{"api_key": "hunter2-Value"}', '{"api_key": "[REDACTED]"}'),
    (
        '{"name":"x","client_secret":"hunter2 Value","n":1}',
        '{"name":"x","client_secret":"[REDACTED]","n":1}',
    ),
    ('{"X-Api-Key" :\n "hunter2-Value"}', '{"X-Api-Key" :\n "[REDACTED]"}'),
    ("{'password': 'hunter2-Value'}", "{'password': '[REDACTED]'}"),
    ('{"Authorization": "hunter2-Value"}', '{"Authorization": "[REDACTED]"}'),
    # generic "name = literal" (config files and source code)
    ('api_key = "hunter2-Value"', 'api_key = "[REDACTED]"'),
    ("password = 'hunter2 Value'", "password = '[REDACTED]'"),
    # quoted escapes must not end the value early
    ('export API_KEY="hunter2\\"Value" ; ls', 'export API_KEY="[REDACTED]" ; ls'),
    ('$env:API_KEY = "hunter2`"Value"', '$env:API_KEY = "[REDACTED]"'),
    ("$env:API_KEY = 'hunter2''Value'", "$env:API_KEY = '[REDACTED]'"),
    # unterminated quote: the rest of the text may be the secret
    ('export API_KEY="hunter2 Value and more', "export API_KEY=[REDACTED]"),
    # --- review findings -------------------------------------------------------------------
    # JSON inside a shell argument or inside a JSON string: the quotes carry backslashes
    (
        'curl -d "{\\"api_key\\": \\"hunter2\\"}" http://x',
        'curl -d "{\\"api_key\\": \\"[REDACTED]\\"}" http://x',
    ),
    (
        'echo \'{\\"password\\": \\"hunter2\\"}\'',
        'echo \'{\\"password\\": \\"[REDACTED]\\"}\'',
    ),
    (
        json.dumps('{"password": "hunter2", "n": 1}'),
        json.dumps('{"password": "hunter2", "n": 1}').replace("hunter2", "[REDACTED]"),
    ),
    (
        json.dumps(json.dumps('{"password": "hunter2"}')),
        json.dumps(json.dumps('{"password": "hunter2"}')).replace("hunter2", "[REDACTED]"),
    ),
    ('{\\"token\\": \\"hunter2 Value', '{\\"token\\": \\"[REDACTED]'),  # unterminated
    ('{\\"token\\": \\"\\"}', '{\\"token\\": \\"\\"}'),  # empty value: nothing to hide
    # subscript and quoted-name assignments
    (
        "python -c \"import os; os.environ['API_KEY']='hunter2'\"",
        "python -c \"import os; os.environ['API_KEY']='[REDACTED]'\"",
    ),
    ('os.environ["API_KEY"] = "hunter2"', 'os.environ["API_KEY"] = "[REDACTED]"'),
    ("env['TOKEN'] = 'hunter2 Value'", "env['TOKEN'] = '[REDACTED]'"),
    ("config[API_KEY] = 'hunter2'", "config[API_KEY] = '[REDACTED]'"),
    ('@{ "api_key" = "hunter2" }', '@{ "api_key" = "[REDACTED]" }'),
    (
        "@{ 'db_password' = 'hunter2 Value'; user = 'x' }",
        "@{ 'db_password' = '[REDACTED]'; user = 'x' }",
    ),
    ('export "API_KEY"=hunter2 && ls', 'export "API_KEY"=[REDACTED] && ls'),
    ("os.putenv('API_KEY', 'hunter2')", "os.putenv('API_KEY', '[REDACTED]')"),
    (
        'os.environ.setdefault("DB_PASSWORD", "hunter2")',
        'os.environ.setdefault("DB_PASSWORD", "[REDACTED]")',
    ),
    # the quote in front of the name is the value's quote too
    ('"API_KEY="hunter2"', '"API_KEY="[REDACTED]"'),
    ("'API_KEY='hunter2'", "'API_KEY='[REDACTED]'"),
    ('docker run -e "TOKEN="hunter2" img', 'docker run -e "TOKEN="[REDACTED]" img'),
    ('FOO="a"BAR_TOKEN="hunter2"', 'FOO="a"BAR_TOKEN="[REDACTED]"'),
    ('set "API_KEY=" & echo "x"', 'set "API_KEY=" & echo "x"'),  # empty enclosed value
    # unquoted values end at ASCII whitespace only; escapes and odd spaces belong to the word
    ("KEY=hunter2\u00a0tail-hunter2 next", "KEY=[REDACTED] next"),
    ("KEY=hunter2\u2028tail-hunter2 next", "KEY=[REDACTED] next"),
    ("KEY=hunter2\u0085tail-hunter2 next", "KEY=[REDACTED] next"),
    ("KEY=hunter2\x1ftail-hunter2 next", "KEY=[REDACTED] next"),
    ("export API_KEY=hunter2\\ tail-hunter2 next", "export API_KEY=[REDACTED] next"),
    ("export PASSWORD=my\\ secret\\ hunter2; ls", "export PASSWORD=[REDACTED] ls"),
    ("export API_KEY=abc\\\nhunter2tail\nnext", "export API_KEY=[REDACTED]\nnext"),
    ('KEY=ab"cd ef"gh-hunter2 next', "KEY=[REDACTED] next"),
    # cmd: "set" stores the rest of the command, spaces around "=" included
    ("set PASSWORD=my hunter2 phrase", "set PASSWORD=[REDACTED]"),
    ("set PASSWORD= hunter2", "set PASSWORD= [REDACTED]"),
    ("set API_KEY = hunter2", "set API_KEY = [REDACTED]"),
    ("set /p MY_TOKEN=hunter2 prompt", "set /p MY_TOKEN=[REDACTED]"),
    ("SET /A db_secret=hunter2 + 1", "SET /A db_secret=[REDACTED]"),
    ("set PASSWORD=hunter2 && echo done", "set PASSWORD=[REDACTED] && echo done"),
    ("set PASSWORD=hunter2 & echo done", "set PASSWORD=[REDACTED] & echo done"),
    ("set PASSWORD=hunter2 | more", "set PASSWORD=[REDACTED] | more"),
    ("set PASSWORD=a^&hunter2 & echo", "set PASSWORD=[REDACTED] & echo"),
    ('set PASSWORD="a & hunter2" & echo', "set PASSWORD=[REDACTED] & echo"),
    (
        "@echo off\r\nset API_KEY=hunter2 x\r\necho ok",
        "@echo off\r\nset API_KEY=[REDACTED]\r\necho ok",
    ),
    ("echo a & set API_KEY=hunter2", "echo a & set API_KEY=[REDACTED]"),
    # a value inside a quoted argument ends at the quote that closes it
    (
        'curl "http://x/?token=hunter2" -o out.txt && echo done',
        'curl "http://x/?token=[REDACTED]" -o out.txt && echo done',
    ),
    (
        'curl "https://api/x?access_token=hunter2&y=1" -H "Accept: json" -o o.json',
        'curl "https://api/x?access_token=[REDACTED]" -H "Accept: json" -o o.json',
    ),
    ("echo 'x?token=hunter2' ok", "echo 'x?token=[REDACTED]' ok"),
    ('bash -c "export API_KEY=hunter2" && ls', 'bash -c "export API_KEY=[REDACTED]" && ls'),
    # PowerShell string concatenation
    ('$env:API_TOKEN = "a1" + "hunter2"', "$env:API_TOKEN = [REDACTED]"),
    ('$env:API_TOKEN = "hunter2" + $suffix; ls', "$env:API_TOKEN = [REDACTED]; ls"),
    ("$env:API_TOKEN = 'a' + 'b' + 'hunter2'", "$env:API_TOKEN = [REDACTED]"),
    (
        "$p = ConvertTo-SecureString 'hunter2' -AsPlainText -Force",
        "$p = ConvertTo-SecureString '[REDACTED]' -AsPlainText -Force",
    ),
    (
        '$p = ConvertTo-SecureString -String "hunter2" -AsPlainText',
        '$p = ConvertTo-SecureString -String "[REDACTED]" -AsPlainText',
    ),
    # command line flags that take a secret as the next word
    ("mysql --password hunter2 -u root", "mysql --password [REDACTED] -u root"),
    ("tool --token 'hunter2 Value' run", "tool --token '[REDACTED]' run"),
    ("tool --api-key hunter2", "tool --api-key [REDACTED]"),
    ("tool --CLIENT-SECRET hunter2 --x", "tool --CLIENT-SECRET [REDACTED] --x"),
]


@pytest.mark.parametrize(("text", "expected"), ASSIGNMENT_CASES)
def test_assignment_forms(text: str, expected: str) -> None:
    out = redact_text(text)
    assert out == expected
    assert "hunter2" not in out
    assert redact_text(out) == out


def test_assignment_case_insensitive_names() -> None:
    for name in [
        "API_KEY",
        "api_key",
        "Api_Key",
        "MYTOKEN",
        "mysecret",
        "PassWord",
        "x_PASSWORD_y",
    ]:
        assert redact_text(f"{name}=hunter2") == f"{name}=[REDACTED]"


def test_pattern_inside_assignment_value_collapses_to_one_redaction() -> None:
    out = redact_text(f"export MY_KEY={SK_KEY} && echo done")
    assert out == "export MY_KEY=[REDACTED] && echo done"


def test_secret_in_an_unrelated_variable_name_is_not_an_assignment_pattern() -> None:
    # The name has no KEY/TOKEN/SECRET/PASSWORD: only the token patterns apply.
    assert redact_text("export HOME=/home/me PATH=/usr/bin") == "export HOME=/home/me PATH=/usr/bin"


# --------------------------------------------------------------------------------------------
# False positives: ordinary text stays exactly as it is
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "ls -la",
        "disk-usage-report-for-the-whole-machine",
        "ask-me-anything-about-the-risk-assessment-for-this-task",
        "sk-short",
        "sk-" + "a" * 15,
        r"C:\Users\someone\Documents\project\src\main.py",
        "/usr/local/lib/python3.12/site-packages/pkg/__init__.py",
        "git log 3f2c1a9e7b6d4c5a8e9f0a1b2c3d4e5f6a7b8c9d",
        "commit 3f2c1a9",
        "123e4567-e89b-12d3-a456-426614174000",
        "AKIA123",
        "ghp_short",
        "github_pat_short",
        "bearer of bad news",
        "the bearer token",
        "BEGIN PRIVATE KEY",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "https://example.com/path?x=1&y=2",
        "ssh://git@github.com:org/repo.git",
        "https://example.com:8080/a@b",
        "mail me at someone@example.com",
        "export PATH=/usr/bin:$PATH",
        "FOO=bar BAZ=qux ./run",
        "$env:PATH = 'C:\\bin'",
        "set NAME=value",
        "setx NAME value",
        "monkey see monkey do",  # contains "key" but is not an assignment
        "if token == expected: pass",
        "tokens = 3",
        "key = value_without_quotes",
        "key: value",
        '{"name": "value", "count": 3}',
        '{"api_key": 12345, "enabled": true, "token": null}',
        "[Environment]::SetEnvironmentVariable('EDITOR','vim')",
        "KEY=",
        "KEY= value",
        'KEY=""',
        "== key ==",
        "-----",
        "\u4e2d\u6587\u6587\u672c \u30c6\u30b9\u30c8",
        # paths and URLs that merely look like credentials
        "file://C:\\Users\\bob@corp\\x",
        "file:///C:/Users/me/x@y",
        "http://example.com/a:b/c@d",
        # comparisons and lookups that are not assignments
        "if d['key'] == x: pass",
        "if d['key']==x:",
        'if os.environ["API_KEY"] == "abc": pass',
        "os.environ['HOME']='/root'",
        "os.putenv('EDITOR', 'vim')",
        "x = {'name': 'a'}",
        # flags that only look like secret flags
        "tool --token-file /tmp/f",
        "ssh-keygen --key-type rsa",
        "tool --password",
        "tool --password --verbose",
        "tool --token=",
        # "set" is only special for the argument right after it
        "reset NAME=abc",
        "echo set the value",
        # headers other than Authorization
        "Accept: application/json",
        "Content-Type: text/plain",
        # an ordinary quoted string that holds no secret
        'echo "hello world" && echo done',
        "[Environment]::SetEnvironmentVariable('EDITOR','vim','User')",
        "ConvertTo-SecureString $existing -AsPlainText",
    ],
)
def test_ordinary_text_is_unchanged(text: str) -> None:
    assert redact_text(text) == text


def test_only_the_secret_part_is_replaced() -> None:
    text = f"prefix text {SK_KEY} suffix text\nsecond line {AWS_ID}\nthird"
    assert redact_text(text) == "prefix text [REDACTED] suffix text\nsecond line [REDACTED]\nthird"


def test_redacted_marker_is_stable() -> None:
    assert REDACTED == "[REDACTED]"
    assert redact_text(REDACTED) == REDACTED
    assert redact_text("KEY=" + REDACTED) == "KEY=" + REDACTED


def test_pattern_unlocked_by_an_earlier_redaction_is_still_redacted() -> None:
    # "sk-" is blocked by the word character before it until the AWS id in front of it is gone.
    text = "AKIA" + "A" * 16 + "sk-" + "b" * 20
    out = redact_text(text)
    assert out == "[REDACTED][REDACTED]"
    assert redact_text(out) == out


def test_non_str_input_does_not_raise() -> None:
    assert redact_text(None) == "None"  # type: ignore[arg-type]
    assert redact_text(123) == "123"  # type: ignore[arg-type]


def test_lone_surrogates_and_nul_do_not_raise() -> None:
    text = "\ud800\udfff\x00KEY=\x00hunter2\x00 \udc00"
    out = redact_text(text)
    assert "hunter2" not in out
    assert redact_text(out) == out


# --------------------------------------------------------------------------------------------
# Hypothesis: idempotence, no exceptions, no change without a secret, the secret never survives
# --------------------------------------------------------------------------------------------

_FRAGMENTS = [
    "sk-",
    "sk-" + "a" * 20,
    "AKIA",
    "AKIA" + "A" * 16,
    "ghp_",
    "ghp_" + "b" * 22,
    "github_pat_",
    "Bearer ",
    "bearer abcdefgh",
    "KEY=",
    "key",
    "TOKEN",
    "password",
    "SECRET=",
    '"',
    "'",
    "`",
    "\\",
    '""',
    "''",
    "$env:",
    "${env:",
    "}",
    " = ",
    "=",
    "+=",
    ":",
    ": ",
    ",",
    ";",
    "(",
    ")",
    "{",
    "setx ",
    "set ",
    "export ",
    "SetEnvironmentVariable(",
    "-----BEGIN PRIVATE KEY-----",
    "-----END PRIVATE KEY-----",
    "-----BEGIN ",
    "://u:",
    "@",
    "/",
    "Authorization: Basic ",
    "[REDACTED]",
    "\n",
    " ",
    "a" * 20,
    "A" * 16,
    "abcdefgh",
    "\x00",
    "\ud800",
    # added with the review fixes: escaped JSON, subscripts, cmd set, flags, non-ASCII neighbours
    '\\"',
    "\\\\",
    "\\ ",
    "\\\n",
    "os.environ[",
    "']",
    '"]',
    "set /p ",
    "--password ",
    "--token=",
    "Authorization: ",
    "ConvertTo-SecureString ",
    "putenv(",
    " + ",
    "&",
    "^",
    "\u00a0",
    "\u2028",
    "密钥",
    "file://",
    "-----begin ",
    "private key-----",
]

fragment_text = st.lists(
    st.one_of(st.sampled_from(_FRAGMENTS), st.text(max_size=12)), max_size=14
).map("".join)
any_text = st.text(
    alphabet=st.characters(exclude_categories=()), max_size=300
)  # includes lone surrogates

# REDACT_FUZZ_EXAMPLES raises the example count for a longer local fuzzing run.
_HYPOTHESIS = settings(
    max_examples=int(os.environ.get("REDACT_FUZZ_EXAMPLES", "300")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@_HYPOTHESIS
@given(st.one_of(fragment_text, any_text))
def test_idempotent(text: str) -> None:
    once = redact_text(text)
    assert redact_text(once) == once


@_HYPOTHESIS
@given(st.one_of(fragment_text, any_text))
def test_never_raises_and_returns_str(text: str) -> None:
    assert isinstance(redact_text(text), str)


# Letters that cannot spell any trigger word: no k, t, s, p, c, e, b, g, r, no uppercase, no ":".
_SAFE = "adfhilmnoquvwxyz0123456789 \n.,;/\\()[]{}=!?#@%^&*+~|<>_\"'-$"


@_HYPOTHESIS
@given(st.text(alphabet=_SAFE, max_size=300))
def test_text_without_secrets_is_unchanged(text: str) -> None:
    assert redact_text(text) == text


_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# Surrounding text is lowercase words and spaces only, so a leaked secret cannot hide inside it.
_AROUND = st.sampled_from(
    ["", "echo before ", "run the job\n", "(", "x ", "result: ", "- ", "\t", "line one\nline two\n"]
)
_AFTER = st.sampled_from(["", " && echo after", "\nnext line", ")", " ", ";", ", more"])

secret_token = st.one_of(
    st.text(alphabet=_ALNUM + "_-", min_size=16, max_size=60).map(lambda s: "sk-" + s),
    st.tuples(
        st.sampled_from(["AKIA", "ASIA"]), st.text(alphabet=_UPPER_DIGITS, min_size=16, max_size=16)
    ).map("".join),
    st.tuples(
        st.sampled_from(["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]),
        st.text(alphabet=_ALNUM, min_size=20, max_size=60),
    ).map("".join),
    st.text(alphabet=_ALNUM + "_", min_size=20, max_size=60).map(lambda s: "github_pat_" + s),
)


@_HYPOTHESIS
@given(_AROUND, secret_token, _AFTER)
def test_token_secret_never_survives(before: str, secret: str, after: str) -> None:
    # The lowercase surrounding text cannot contain a 16+ character secret by accident.
    text = f"{before}{secret}{after}"
    out = redact_text(text)
    assert secret not in out
    assert REDACTED in out


@_HYPOTHESIS
@given(
    _AROUND,
    st.text(alphabet=_ALNUM + "._~+/=-", min_size=8, max_size=40),
    st.sampled_from(["Bearer", "bearer", "BEARER", "BeArEr"]),
    _AFTER,
)
def test_bearer_secret_never_survives(before: str, token: str, word: str, after: str) -> None:
    out = redact_text(f"{before}Authorization: {word} {token}{after}")
    # The token may be spelled "REDACTED" (hypothesis tried it): ignore the marker itself.
    assert token not in out.replace(REDACTED, "")
    assert out.endswith(f"{word} {REDACTED}{after}")


@_HYPOTHESIS
@given(
    _AROUND,
    st.sampled_from(["PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY"]),
    st.lists(st.text(alphabet=_ALNUM + "+/=", min_size=20, max_size=64), min_size=1, max_size=5),
    st.booleans(),
    _AFTER,
)
def test_private_key_never_survives(
    before: str, kind: str, body_lines: list[str], terminated: bool, after: str
) -> None:
    end = f"\n-----END {kind}-----" if terminated else ""
    block = f"-----BEGIN {kind}-----\n" + "\n".join(body_lines) + end
    out = redact_text(f"{before}{block}{after}")
    for line in body_lines:
        assert line not in out
    assert "PRIVATE KEY" not in out


_NAMES = st.sampled_from(
    [
        "MY_API_KEY",
        "GithubToken",
        "db_password",
        "AWS_SECRET_ACCESS_KEY",
        "passwd",
        "apiKey",
        "SECRET",
        "x-auth-token",
        "KEYCHAIN_PASS",
    ]
)
# Values use characters that no name or surrounding text contains (Q, Z, X, digits, symbols).
_VALUE = st.text(alphabet="QZX0123456789#%^*+!", min_size=6, max_size=24)
_QUOTED_VALUE = st.text(alphabet="QZX0123456789#%^*+! ", min_size=6, max_size=24).filter(
    lambda s: len(s.strip()) >= 4
)

_UNQUOTED_TEMPLATES = [
    "{n}={v}",
    "export {n}={v}",
    "$env:{n} = {v}",
    "set {n}={v}",
    "setx {n} {v}",
    "curl --{n}={v} https://example.invalid",
]
_QUOTED_TEMPLATES = [
    '{n}="{v}"',
    "{n}='{v}'",
    'export {n}="{v}"',
    "export {n}='{v}'",
    '$env:{n} = "{v}"',
    "$env:{n}='{v}'",
    '${{env:{n}}} = "{v}"',
    "${{env:{n}}}='{v}'",
    'set "{n}={v}"',
    'setx {n} "{v}"',
    "setx {n} '{v}'",
    '[Environment]::SetEnvironmentVariable("{n}","{v}","User")',
    "[System.Environment]::SetEnvironmentVariable('{n}','{v}')",
    '{{"{n}": "{v}"}}',
    "{{'{n}': '{v}'}}",
    '{n} = "{v}"',
    "{n} = '{v}'",
]


@_HYPOTHESIS
@given(_AROUND, st.sampled_from(_UNQUOTED_TEMPLATES), _NAMES, _VALUE, _AFTER)
def test_unquoted_assignment_value_never_survives(
    before: str, template: str, name: str, value: str, after: str
) -> None:
    out = redact_text(before + template.format(n=name, v=value) + after)
    assert value not in out
    assert name in out


@_HYPOTHESIS
@given(_AROUND, st.sampled_from(_QUOTED_TEMPLATES), _NAMES, _QUOTED_VALUE, _AFTER)
def test_quoted_assignment_value_never_survives(
    before: str, template: str, name: str, value: str, after: str
) -> None:
    out = redact_text(before + template.format(n=name, v=value) + after)
    assert value not in out
    assert value.strip() not in out
    assert name in out


@_HYPOTHESIS
@given(_AROUND, _VALUE, _AFTER)
def test_url_password_never_survives(before: str, password: str, after: str) -> None:
    out = redact_text(f"{before}postgres://user:{password}@host/db{after}")
    assert password not in out
    assert "user:" in out


# --------------------------------------------------------------------------------------------
# Hostile input: linear time
# --------------------------------------------------------------------------------------------

_MB2 = 2_000_000
_BUDGET_SECONDS = 2.0

_HOSTILE = {
    "sk-": "sk-" * 700_000,
    "A": "A" * _MB2,
    "=": "=" * _MB2,
    "$env:": "$env:" * 400_000,
    "unterminated-quotes": '"' * _MB2,
    "unterminated-single-quotes": "'" * _MB2,
    "begin-private-key": "-----BEGIN PRIVATE KEY-----" * 70_000,
    "begin-without-header": "-----BEGIN " * 180_000,
    "bearer": "Bearer " * 280_000,
    "KEY=": "KEY=" * 500_000,
    "key-keyword-soup": "key" * 700_000,
    "key-and-spaces": "key " * 500_000,
    "assignment-then-open-quote": 'KEY="' * 400_000,
    "assignment-then-single-quote": "KEY='" * 400_000,
    "assignment-one-open-quote": "KEY=" + '"' * _MB2,
    "assignment-backslashes": 'KEY="' + "\\" * _MB2,
    "assignment-doubled-quotes": 'KEY="' + '""' * 1_000_000,
    "spaces-before-equals": "KEY" + " " * _MB2 + "=",
    "setx": "setx " * 400_000,
    "setenvironmentvariable": "SetEnvironmentVariable(" * 90_000,
    "url-userinfo": "://a:" * 400_000,
    "authorization": "authorization " * 150_000,
    "words": "hello world " * 170_000,
}

# Slower to chew through (many separate candidates) but still linear; half the size.
_HOSTILE_MANY_CANDIDATES = {
    "assignments-empty-values": "KEY= " * 200_000,
    "ps-assignments": "$env:KEY = x " * 75_000,
    "json-pairs": '"a_key": "x", ' * 70_000,
    "json-keys-only": '"a_key":' * 125_000,
    "setx-names": "setx KEY " * 100_000,
}


@pytest.mark.parametrize("name", sorted(_HOSTILE))
def test_linear_time_on_hostile_input(name: str) -> None:
    text = _HOSTILE[name]
    start = time.perf_counter()
    out = redact_text(text)
    elapsed = time.perf_counter() - start
    assert elapsed < _BUDGET_SECONDS, f"{name}: {elapsed:.2f}s"
    assert isinstance(out, str)


@pytest.mark.parametrize("name", sorted(_HOSTILE_MANY_CANDIDATES))
def test_linear_time_on_many_candidates(name: str) -> None:
    text = _HOSTILE_MANY_CANDIDATES[name]
    start = time.perf_counter()
    redact_text(text)
    elapsed = time.perf_counter() - start
    assert elapsed < _BUDGET_SECONDS, f"{name}: {elapsed:.2f}s"


def test_hostile_inputs_still_redact() -> None:
    assert redact_text("sk-" * 700_000) == REDACTED
    assert redact_text("KEY=" * 500_000) == "KEY=" + REDACTED
    assert redact_text("-----BEGIN PRIVATE KEY-----" * 1000) == REDACTED
    assert redact_text("Bearer " + "A" * _MB2) == "Bearer " + REDACTED


def test_large_text_with_secret_in_the_middle() -> None:
    filler = "lorem ipsum dolor amet " * 40_000
    out = redact_text(f"{filler}export API_KEY=hunter2 {filler}{SK_KEY} {filler}")
    assert "hunter2" not in out
    assert SK_KEY not in out
    assert out.count(REDACTED) == 2
    assert out.startswith(filler)
    assert out.endswith(filler)


# --------------------------------------------------------------------------------------------
# redact_obj
# --------------------------------------------------------------------------------------------


def test_redact_obj_walks_dict_list_tuple_and_keeps_scalars() -> None:
    obj = {
        "cmd": f"curl -H 'x: {SK_KEY}'",
        "n": 3,
        "f": 1.5,
        "ok": True,
        "none": None,
        "list": [f"ghp_{'a' * 25}", 7, ("MY_TOKEN=abc", None)],
        "nested": {"deeper": {"s": AWS_ID}},
    }
    out = redact_obj(obj)
    assert out == {
        "cmd": "curl -H 'x: [REDACTED]'",
        "n": 3,
        "f": 1.5,
        "ok": True,
        "none": None,
        "list": [REDACTED, 7, ("MY_TOKEN=[REDACTED]", None)],
        "nested": {"deeper": {"s": REDACTED}},
    }
    assert isinstance(out, dict)
    assert isinstance(out["list"], list)
    assert isinstance(out["list"][2], tuple)


def test_redact_obj_never_mutates_and_returns_new_containers() -> None:
    obj = {"a": [f"{SK_KEY}", {"b": "x"}], "api_key": "hunter2"}
    snapshot = copy.deepcopy(obj)
    out = redact_obj(obj)
    assert obj == snapshot
    assert out is not obj
    assert isinstance(out, dict)
    assert out["a"] is not obj["a"]
    assert out["a"][1] is not obj["a"][1]  # type: ignore[index]


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "API_KEY",
        "token",
        "access_token",
        "Secret",
        "client_secret",
        "password",
        "passwd",
        "Authorization",
        "credentials",
        "my-Credential-id",
        "apikey",
        "KeyId",
    ],
)
def test_redact_obj_sensitive_key_replaces_string_value(key: str) -> None:
    assert redact_obj({key: "hunter2"}) == {key: REDACTED}
    assert redact_obj({key: ""}) == {key: REDACTED}


def test_redact_obj_sensitive_key_leaves_non_strings_alone() -> None:
    out = redact_obj({"token": 12345, "api_key": None, "secret": True, "password": 1.5})
    assert out == {"token": 12345, "api_key": None, "secret": True, "password": 1.5}


def test_redact_obj_sensitive_key_still_walks_nested_containers() -> None:
    obj = {
        "credentials": {"user": "me", "note": f"x {AWS_ID}", "password": "p"},
        "tokens": [SK_KEY],
    }
    out = redact_obj(obj)
    assert out == {
        "credentials": {"user": "me", "note": "x [REDACTED]", "password": REDACTED},
        "tokens": [REDACTED],
    }


def test_redact_obj_ordinary_keys_keep_ordinary_strings() -> None:
    obj = {"tool": "Bash", "command": "ls -la", "cwd": "C:\\work"}
    assert redact_obj(obj) == obj


def test_redact_obj_secret_in_a_key_is_redacted() -> None:
    out = redact_obj({SK_KEY: 1})
    assert out == {REDACTED: 1}


def test_redact_obj_non_string_keys() -> None:
    class Weird:
        def __repr__(self) -> str:
            return "Weird(MY_TOKEN=abc)"

    out = redact_obj({1: "a", None: "b", 2.5: "c", (1, 2): "d", Weird(): "e"})
    assert isinstance(out, dict)
    assert out[1] == "a"
    assert out[None] == "b"
    assert out[2.5] == "c"
    assert out["(1, 2)"] == "d"
    # An unquoted value runs to the next whitespace, so the ")" goes with it (fail closed).
    assert "Weird(MY_TOKEN=[REDACTED]" in out
    assert "abc" not in repr(out)


def test_redact_obj_depth_limit() -> None:
    deep: object = "bottom"
    for _ in range(40):
        deep = [deep]
    out = redact_obj(deep)
    node: object = out
    depth = 0
    while isinstance(node, list):
        node = node[0]
        depth += 1
    assert node == TRUNCATED
    assert depth == 33  # root is depth 0; depth 33 is the first level past max_depth=32


def test_redact_obj_custom_max_depth() -> None:
    assert redact_obj({"a": {"b": "x"}}, max_depth=1) == {"a": {"b": TRUNCATED}}
    assert redact_obj({"a": {"b": "x"}}, max_depth=2) == {"a": {"b": "x"}}
    assert redact_obj("flat", max_depth=0) == "flat"
    assert redact_obj(["x"], max_depth=0) == [TRUNCATED]


def test_redact_obj_cyclic_list_does_not_hang() -> None:
    loop: list[object] = []
    loop.append(loop)
    loop.append(loop)
    start = time.perf_counter()
    out = redact_obj(loop)
    assert time.perf_counter() - start < 1.0
    assert out == [TRUNCATED, TRUNCATED]


def test_redact_obj_cyclic_dict_does_not_hang() -> None:
    d: dict[str, object] = {"name": "x", "token": "t"}
    d["self"] = d
    d["also"] = [d, d]
    start = time.perf_counter()
    out = redact_obj(d)
    assert time.perf_counter() - start < 1.0
    assert out == {
        "name": "x",
        "token": REDACTED,
        "self": TRUNCATED,
        "also": [TRUNCATED, TRUNCATED],
    }


def test_redact_obj_shared_substructure_is_not_a_cycle() -> None:
    shared = ["x"]
    assert redact_obj([shared, shared]) == [["x"], ["x"]]


def test_redact_obj_exponential_sharing_is_bounded() -> None:
    node: object = ["leaf"]
    for _ in range(60):
        node = [node, node]
    start = time.perf_counter()
    out = redact_obj(node, max_depth=100)
    assert time.perf_counter() - start < 5.0
    assert isinstance(out, list)


def test_redact_obj_non_json_objects_become_redacted_repr() -> None:
    class Thing:
        def __repr__(self) -> str:
            return "Thing(api_key='abc', sk=sk-0123456789abcdef0123)"

    out = redact_obj({"a": Thing(), "b": {1, 2}, "c": b"bytes", "d": complex(1, 2)})
    assert isinstance(out, dict)
    assert "sk-0123456789abcdef0123" not in repr(out)
    assert out["b"] in ("{1, 2}", "{2, 1}")
    assert out["c"] == "b'bytes'"
    assert out["d"] == "(1+2j)"


def test_redact_obj_hostile_repr_does_not_raise() -> None:
    class Bad:
        def __repr__(self) -> str:
            raise RuntimeError("boom")

    out = redact_obj([Bad(), {Bad(): 1}])
    assert out == ["<unrepresentable Bad>", {"<unrepresentable Bad>": 1}]


def test_redact_obj_top_level_values() -> None:
    assert redact_obj("export MY_KEY=abc") == "export MY_KEY=[REDACTED]"
    assert redact_obj(5) == 5
    assert redact_obj(None) is None
    assert redact_obj([]) == []
    assert redact_obj({}) == {}


def test_redact_obj_str_subclass_becomes_plain_str() -> None:
    class Name(str):
        __slots__ = ()

    out = redact_obj([Name("hello")])
    assert out == ["hello"]
    assert isinstance(out, list)
    assert type(out[0]) is str


json_leaf = st.one_of(
    st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=30)
)
json_tree = st.recursive(
    json_leaf,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=10), children, max_size=4),
    ),
    max_leaves=25,
)


@_HYPOTHESIS
@given(json_tree)
def test_redact_obj_is_idempotent_and_does_not_mutate(tree: object) -> None:
    snapshot = copy.deepcopy(tree)
    once = redact_obj(tree)
    assert tree == snapshot
    assert redact_obj(once) == once


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        # The vendor prefixes are joined at run time: a complete token-shaped literal in the source
        # trips GitHub push protection even though these are made-up values.
        ("slack " + "xox" + "b-123456789012-abcdefABCDEF1234", "abcdefABCDEF1234"),
        (
            "key " + "AIza" + "SyA-1234567890abcdefghijklmnopqrstu",
            "1234567890abcdefghijklmnopqrstu",
        ),
        ("stripe " + "sk_" + "live_abcdef1234567890ABCD", "abcdef1234567890ABCD"),
        (
            "npm " + "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789",
            "abcdefghijklmnopqrstuvwxyz0123456789",
        ),
        ("gitlab " + "glpat" + "-abcdefghij0123456789", "abcdefghij0123456789"),
        (
            "jwt "
            + "eyJ"
            + "hbGciOiJIUzI1NiJ9."
            + "eyJ"
            + "zdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p",
            "dBjftJeZ4CVPmB92K27uhbUJU1p",
        ),
        ('curl -H "X-Api-Key: hunter2hunter2" https://x', "hunter2hunter2"),
        ("curl -H 'X-Auth-Token: hunter2hunter2'", "hunter2hunter2"),
        ("mytool --pass hunter2hunter2 --verbose", "hunter2hunter2"),
        ("mytool --passphrase hunter2hunter2", "hunter2hunter2"),
    ],
)
def test_vendor_tokens_and_custom_credential_headers_are_redacted(text: str, secret: str) -> None:
    redacted = redact_text(text)
    assert secret not in redacted
    assert "[REDACTED]" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "mytool --passthrough on",
        "xargs --max-args 5",
        "git log --pretty=oneline",
        "npm install left-pad",
    ],
)
def test_the_new_patterns_leave_ordinary_commands_alone(text: str) -> None:
    assert redact_text(text) == text
