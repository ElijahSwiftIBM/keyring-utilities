import pydatalib

cert_admin = pydatalib.CertAdmin(debug=True)

cert_admin.extract_certificate(userid="ESWIFT",keyring="ETESTRNG",label="ElijahTestCert04")
cert_admin.extract_certificate(userid="ESWIFT",keyring="ETESTRNG",label="ElijahTestCert04", base_64_encoding=True)

cert_admin.list_keyring(userid="ESWIFT",keyring="ETESTRNG")
cert_admin.list_keyring(userid="ESWIFT",keyring="ETESTRNG", base_64_encoding=True)
