"""A sample file for testing the library's base functions."""
import pydatalib

cert_admin = pydatalib.CertAdmin(debug=True)

user_name = "ESWIFT"
key_ring_1 = "ETESTRNG"
key_ring_2 = "ETESTRG1"

cert_admin.extract_certificate(
    userid=user_name, keyring=key_ring_1, label="ElijahTestCert04"
)
cert_admin.extract_certificate(
    userid=user_name,
    keyring=key_ring_1,
    label="ElijahTestCert04",
    base_64_encoding=True,
)

cert_admin.list_keyring(userid=user_name, keyring=key_ring_1)
cert_admin.list_keyring(userid=user_name, keyring=key_ring_1, base_64_encoding=True)

cert_admin.add_keyring(userid=user_name, keyring=key_ring_2)

#cert_admin.list_keyring(userid=user_name, keyring=key_ring_2)
#cert_admin.list_keyring(userid=user_name, keyring=key_ring_2, base_64_encoding=True)

cert_admin.delete_certificate(
    userid=user_name, keyring=key_ring_1, label="ElijahTestCert05"
)

cert_admin.list_keyring(userid=user_name, keyring=key_ring_1, base_64_encoding=True)

cert_admin.delete_keyring(userid=user_name, keyring=key_ring_2)
