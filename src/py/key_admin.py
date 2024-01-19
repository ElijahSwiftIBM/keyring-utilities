import base64
from typing import List

import cpydatalib
import ebcdic

from .datalib_service_error import DatalibServiceError


class KeyAdmin:
    """Base (and only) class for Key/Keyring Administration Interface"""

    def __init__(self, debug=False, codepage="cp1047") -> None:
        self.__codepage = codepage
        self.__debug = debug

    def extract_certificate(
        self, userid: str, keyring: str, label: str, base_64_encoding: bool = False
    ) -> dict:
        """Extracts single certificate with known owner, label and keyring."""
        userid = userid.encode(self.__codepage)
        keyring = keyring.encode(self.__codepage)
        label = label.encode(self.__codepage)

        result = cpydatalib.getData(userid=userid, keyring=keyring, label=label)

        if "functionCode" in result:
            raise DatalibServiceError(result)

        if base_64_encoding:
            result["certificate"] = self.__base_64_encode(result["certificate"])
            result["privateKey"] = self.__base_64_encode(
                result["privateKey"], field="privateKey"
            )
        return result

    def list_keyring(
        self, userid: str, keyring: str, base_64_encoding: bool = False
    ) -> List:
        """List information from all certificates on known keyring belonging to known owner."""
        userid = userid.encode(self.__codepage)
        keyring = keyring.encode(self.__codepage)

        result = cpydatalib.listKeyring(userid=userid, keyring=keyring)

        if "functionCode" in result:
            raise DatalibServiceError(result)

        for index in range(len(result)):
            result[index]["label"] = result[index]["label"].decode(self.__codepage)
            result[index]["owner"] = result[index]["owner"].decode(self.__codepage)
            if base_64_encoding:
                result[index]["certificate"] = self.__base_64_encode(
                    result[index]["certificate"]
                )

        return result

    def __base_64_encode(self, data: bytes, field: str = "certificate"):
        """Encodes bytes arrays in base 64 as certificate data or fields need."""
        match field:
            case "certificate":
                result_str = "-----BEGIN CERTIFICATE-----\n"
                result_str = result_str + str(base64.b64encode(data))
                result_str = result_str + "\n-----END CERTIFICATE-----"
            case "privateKey":
                result_str = "-----BEGIN PRIVATE KEY-----\n"
                result_str = result_str + str(base64.b64encode(data))
                result_str = result_str + "\n-----END PRIVATE KEY-----"
            case "encryptedPrivateKey":
                result_str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                result_str = result_str + str(base64.b64encode(data))
                result_str = result_str + "\n-----END ENCRYPTED PRIVATE KEY-----"
            case _:
                result_str = str(base64.b64encode(data))
        return result_str
