import pytest

from implementations.mv_elgamal import MVElGamal


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
def test_elgamal(plain_text):
    encryptor = MVElGamal(bit_size=1024)
    encrypted_text = encryptor.encrypt(
        message=plain_text,
        public_parameters=encryptor.get_public_parameters(),
        public_key=encryptor.get_public_key(),
    )
    output = encryptor.decrypt(
        cipher_text=encrypted_text,
    )
    assert output == plain_text
