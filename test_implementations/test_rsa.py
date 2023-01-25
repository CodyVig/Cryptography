import pytest

from implementations.rsa import RSA


@pytest.mark.parametrize(
    "plain_text",
    [
        "Hello World",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        + "Donec porta ipsum in porttitor sodales.",
        ":@,|.?_\]';>^+,;@$\<)[%=%;^=!#",
    ],
    ids=["english", "lorem", "special_characters"],
)
def test_rsa(plain_text):
    encryptor = RSA(bit_size=512)
    output = encryptor.decrypt(
        encryptor.encrypt(message=plain_text, pub_key=encryptor.get_public_key())
    )
    assert output == plain_text
