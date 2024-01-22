import pydatalib

cert_admin = pydatalib.CertAdmin()

test1 = cert_admin.extract_certificate(userid="ESWIFT",keyring="ETESTRNG",label="ElijahTestCert04")
test1b64 = cert_admin.extract_certificate(userid="ESWIFT",keyring="ETESTRNG",label="ElijahTestCert04", base_64_encoding=True)

test2 = cert_admin.list_keyring(userid="ESWIFT",keyring="ETESTRNG")
test2b64 = cert_admin.list_keyring(userid="ESWIFT",keyring="ETESTRNG")

print(test1)
print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
print(test1b64)
print("\n\n\n\n")

print(test2)
print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
print(test2b64)