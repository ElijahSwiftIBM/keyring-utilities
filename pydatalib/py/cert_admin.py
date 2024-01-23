import base64
import os
from typing import List

import cpydatalib
import ebcdic

from .datalib_service_error import DatalibServiceError


class CertAdmin:
    """Base (and only) class for Key/Keyring Administration Interface"""

    def __init__(self, debug=False, codepage="cp1047") -> None:
        self.__codepage = codepage
        self.__debug = debug

    def extract_certificate(
        self, userid: str, keyring: str, label: str, base_64_encoding: bool = False
    ) -> dict:
        """Extracts single certificate with known owner, label and keyring."""
        if self.__debug:
            print(
                f"Extracting certificate information for {label} from {userid}/{keyring}"
            )

        userid_enc = userid.encode(self.__codepage)
        keyring_enc = keyring.encode(self.__codepage)
        label_enc = label.encode(self.__codepage)

        result = cpydatalib.getData(
            userid=userid_enc, keyring=keyring_enc, label=label_enc
        )

        if "functionCode" in result:
            raise DatalibServiceError(result)

        if base_64_encoding:
            result["certificate"] = self.__base_64_encode(result["certificate"])
            result["privateKey"] = self.__base_64_encode(
                result["privateKey"], field="privateKey"
            )
        if self.__debug:
            print(
                f"Certificate information for {label} from {userid}/{keyring}:\n"
                + f"Certificate: \n{result['certificate']}\n"
                + f"Private Key: \n{result['privateKey']}\n"
            )
        return result

    def list_keyring(
        self, userid: str, keyring: str, base_64_encoding: bool = False
    ) -> List:
        """List information from all certificates on known keyring belonging to known owner."""
        if self.__debug:
            print(f"Listing certificate information for {userid}/{keyring}")

        userid_enc = userid.encode(self.__codepage)
        keyring_enc = keyring.encode(self.__codepage)

        result = cpydatalib.listKeyring(userid=userid_enc, keyring=keyring_enc)

        if "functionCode" in result:
            raise DatalibServiceError(result)

        for index in range(len(result)):
            result[index]["label"] = result[index]["label"].decode(self.__codepage)
            result[index]["owner"] = result[index]["owner"].decode(self.__codepage)
            if base_64_encoding:
                result[index]["certificate"] = self.__base_64_encode(
                    result[index]["certificate"]
                )
        if self.__debug:
            print(f"Certificate information for {userid}/{keyring}:")
            for certificate in result:
                print(
                    f"Label: {certificate['label']}\n"
                    + f"Owner: {certificate['owner']}\n"
                    + f"Usage: {certificate['usage']}\n"
                    + f"Status: {certificate['status']}\n"
                    + f"Default: {certificate['default']}\n"
                    + f"Certificate: \n{certificate['certificate']}\n"
                )
        return result

    def refresh_keyring(self, userid: str, keyring: str) -> None:
        """Refresh the specified Keyring."""
        if self.__debug:
            print(f"Refreshing keyring {userid}/{keyring}")
        userid_enc = userid.encode(self.__codepage)
        keyring_enc = keyring.encode(self.__codepage)

        refresh_code = 11
        result = cpydatalib.touchKeyring(
            userid=userid_enc, keyring=keyring_enc, function_code=refresh_code
        )

        if not (result == 0):
            raise DatalibServiceError(result)
        if self.__debug:
            print(f"Refreshed keyring {keyring} for {userid}")

    def add_keyring(self, userid: str, keyring: str) -> None:
        """Add the specified Keyring."""
        if self.__debug:
            print(f"Adding {userid}/{keyring}")
        userid_enc = userid.encode(self.__codepage)
        keyring_enc = keyring.encode(self.__codepage)

        add_code = 7
        result = cpydatalib.touchKeyring(
            userid=userid_enc, keyring=keyring_enc, function_code=add_code
        )

        if not (result == 0):
            raise DatalibServiceError(result)
        if self.__debug:
            print(f"Added keyring {keyring} to {userid}")

    def delete_keyring(self, userid: str, keyring: str) -> None:
        """Delete the specified Keyring."""
        if self.__debug:
            print(f"Deleting {userid}/{keyring}")
        userid_enc = userid.encode(self.__codepage)
        keyring_enc = keyring.encode(self.__codepage)

        delete_code = 10
        result = cpydatalib.touchKeyring(
            userid=userid_enc, keyring=keyring_enc, function_code=delete_code
        )

        if not (result == 0):
            raise DatalibServiceError(result)
        if self.__debug:
            print(f"Deleted keyring {keyring} from {userid}")

    def delete_certificate(self, userid: str, keyring: str, label: str) -> None:
        """Deletes a single certificate with known owner, label and keyring."""
        if self.__debug:
            print(f"Deleting certificate {label} from {userid}/{keyring}")

        userid_enc = userid.encode(self.__codepage)
        keyring_enc = keyring.encode(self.__codepage)
        label_enc = label.encode(self.__codepage)

        result = cpydatalib.dataRemove(
            userid=userid_enc, keyring=keyring_enc, label=label_enc
        )

        if not (result == 0):
            if not (
                result["safReturnCode"] == 4
                and result["racfReturnCode"] == 4
                and result["racfReasonCode"] == 12
            ):
                raise DatalibServiceError(result)
            self.refresh_keyring(userid=userid, keyring=keyring)
        if self.__debug:
            print(f"Deleted certificate {label} from {userid}/{keyring}")

    def export_certificate(
        self,
        userid: str,
        keyring: str,
        label: str,
        filename: str = "",
        base_64_encoding: bool = False,
        directory: str = os.getcwd(),
    ) -> dict:
        """Exports single certificate with known owner, label and keyring."""
        if filename == "":
            filename = label
        full_path = f"{directory}/{filename}.pem"
        if self.__debug:
            print(
                f"Exporting certificate information for {label} from "
                + f"{userid}/{keyring} to {full_path}"
            )

        certificate_package = self.extract_certificate(
            userid=userid,
            keyring=keyring,
            label=label,
            base_64_encoding=base_64_encoding,
        )
        if os.path.exists(full_path):
            raise FileExistsError(
                f"Cannot export certificate to {full_path} as this file already exists."
            )
        if base_64_encoding:
            file = open(full_path, "w")
        else:
            file = open(full_path, "wb")
        file.write(certificate_package["certificate"])
        file.write(certificate_package["privateKey"])
        file.close()
        if self.__debug:
            print(
                f"Exported certificate information for {label} from "
                + f"{userid}/{keyring} to {full_path}.\n"
                + f"Certificate: \n{certificate_package['certificate']}\n"
                + f"Private Key: \n{certificate_package['privateKey']}\n"
            )

    def import_certificate(
        self,
        userid: str,
        keyring: str,
        label: str,
        filepath: str,
        base_64_encoding: bool = False,
    ) -> dict:
        """Imports a single certificate into RACF with specified owner, label and keyring."""
        if not os.path.isfile(filepath):
            if not os.path.isfile(f"{os.getcwd()}/{filepath}"):
                raise FileNotFoundError(
                    f"Cannot find certificate at {filepath} or at {os.getcwd()}/{filepath}."
                )
            filepath = f"{os.getcwd()}/{filepath}"
        if self.__debug:
            print(
                f"Importing certificate information to {label} under "
                + f"{userid}/{keyring} from {filepath}"
            )

        with open(filepath, "rb") as file:
            file_data = file.readlines()
            file_data_nolines = file.read()

        if self.__debug:
            print(file_data)
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            print(file_data_nolines)

        if not base_64_encoding:
            certificate_data = file_data[0]
            private_key = file_data[1]
        else:
            certificate_data = base64.b64decode(file_data[1])
            private_key = base64.b64decode(file_data[4])

        self._add_certificate(
            userid=userid,
            keyring=keyring,
            label=label,
            certificate_data=certificate_data,
            private_key=private_key,
        )

        if self.__debug:
            print(
                f"Added certificate information to {label} under {userid}/{keyring}\n"
                + f"Base 64 Encoding: {base_64_encoding}\n"
                + f"Certificate: \n{certificate_data}\n"
                + f"Private Key: \n{private_key}\n"
            )

    def _add_certificate(
        self,
        userid: str,
        keyring: str,
        label: str,
        certificate_data: bytes,
        private_key: bytes,
    ) -> None:
        """Adds a single certificate into RACF with specified owner, label and keyring."""
        if self.__debug:
            print(
                f"Adding certificate information to {label} under {userid}/{keyring}\n"
                + f"Certificate: \n{certificate_data}\n"
                + f"Private Key: \n{private_key}\n"
            )
        userid_enc = userid.encode(self.__codepage)
        keyring_enc = keyring.encode(self.__codepage)
        label_enc = label.encode(self.__codepage)

        result = cpydatalib.dataPut(
            userid=userid_enc,
            keyring=keyring_enc,
            label=label_enc,
            certificate=certificate_data,
            private_key=private_key,
        )

        if not (result == 0):
            raise DatalibServiceError(result)
        if self.__debug:
            print(
                f"Added certificate information to {label} under {userid}/{keyring}\n"
                + f"Certificate: \n{certificate_data}\n"
                + f"Private Key: \n{private_key}\n"
            )

    def __base_64_encode(self, data: bytes, field: str = "certificate"):
        """Encodes bytes arrays in base 64 as certificate data or fields need."""
        match field:
            case "certificate":
                result_str = "-----BEGIN CERTIFICATE-----\n"
                result_str = result_str + base64.b64encode(data).decode("utf-8")
                result_str = result_str + "\n-----END CERTIFICATE-----\n"
            case "privateKey":
                result_str = "-----BEGIN PRIVATE KEY-----\n"
                result_str = result_str + base64.b64encode(data).decode("utf-8")
                result_str = result_str + "\n-----END PRIVATE KEY-----\n"
            # No code reaches this case yet, but this was added for potential future use.
            case "encryptedPrivateKey":
                result_str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                result_str = result_str + base64.b64encode(data).decode("utf-8")
                result_str = result_str + "\n-----END ENCRYPTED PRIVATE KEY-----\n"
            case _:
                result_str = str(base64.b64encode(data))
        return result_str
