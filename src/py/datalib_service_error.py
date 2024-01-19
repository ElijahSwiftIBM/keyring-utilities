"""Exception to use when R_Datalib callable service gives a non-zero SAF Return code."""


class DatalibServiceError(Exception):
    """
    Raised when R_datalib yields a non-zero SAF return code for the specified operation.
    """

    def __init__(self, return_codes: dict) -> None:
        self.return_codes = return_codes
        self.evaluate_return_codes()
        self.message = f"({self.__class__.__name__}) {self.message}"

    def __str__(self) -> str:
        return self.message

    def evaluate_return_codes(self):
        self.message = (
            "Security request made to IRRSMO00 failed.\n"
            + f"Function Code: {self.return_codes['functionCode']}\n"
            + f"SAF Return Code: {self.return_codes['safReturnCode']}\n"
            + f"RACF Return Code: {self.return_codes['racfReturnCode']}\n"
            + f"RACF Reason Code: {self.return_codes['racfReasonCode']}\n\n"
        )

        match self.return_codes:
            # R_datalib return and reason codes
            case {"safReturnCode": 4, "racfReturnCode": 0, "racfReasonCode": 0}:
                self.message = self.message + "RACF is not installed."
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 4}:
                self.message = (
                    self.message
                    + "Parameter list error occurred. Attributes were not specified as 0 or the "
                    + "last word in the parameter list did not have the higher order bit on."
                )
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 8}:
                self.message = (
                    self.message + "Not RACF-authorized to use the requested service."
                )
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 12}:
                self.message = (
                    self.message + "Internal error caused recovery to get control."
                )
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 16}:
                self.message = (
                    self.message + "Unable to establish a recovery environment."
                )
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 20}:
                self.message = self.message + "Requested Function_code not defined."
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 24}:
                self.message = self.message + "Parm_list_version number not supported."
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 28}:
                self.message = (
                    self.message
                    + "Error in Ring_name or RACF_userid parameter (Note: Ring_name value "
                    + "is case sensitive)."
                )
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 72}:
                self.message = self.message + "Caller not in task mode."
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 92}:
                self.message = self.message + "Other internal error."
            case {"safReturnCode": 8, "racfReturnCode": 8, "racfReasonCode": 96}:
                self.message = (
                    self.message
                    + "The linklib (steplib or joblib) concatenation contains a non-APF "
                    + "authorized library."
                )
            case {"safReturnCode": 8, "racfReturnCode": 12}:
                icsf_codes = str(hex(self.return_codes["racfReasonCode"]))
                icsf_return_code = icsf_codes[-6:-4]
                icsf_reason_code = icsf_codes[-4:]
                self.message = (
                    self.message
                    + "An unexpected error is returned from ICSF. The hexadecimal reason "
                    + "code value is formatted as follows:\n"
                    + f"{icsf_return_code} - ICSF return code\n"
                    + f"{icsf_reason_code} - ICSF reason code\n"
                )
            # DataGetFirst, DataGetNext and DataAbortQuery Return and Reason Codes
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
            ):
                self.message = (
                    self.message
                    + "Length error in attribute_length, Record_ID_length, label_length, "
                    + "or CERT_user_ID."
                )
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
                | {
                    "functionCode": 3,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
            ):
                self.message = (
                    self.message
                    + "dbToken error. The token may be zero, in use by another task, or may "
                    + "have been created by another task."
                )
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
                | {
                    "functionCode": 3,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
            ):
                self.message = self.message + "Internal error while validating dbToken."
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 44,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 44,
                }
            ):
                self.message = (
                    self.message + "No certificate found with the specified status."
                )
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 48,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 48,
                }
            ):
                self.message = (
                    self.message
                    + "An output area is not long enough. One or more of the following input "
                    + "length fields were too small: Certificate_length, Private_key_length, "
                    + "or Subjects_DN_length. The length field(s) returned contain the amount "
                    + "of storage needed for the service to successfully return data."
                )
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 52,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 52,
                }
            ):
                self.message = (
                    self.message
                    + "Internal error while obtaining record private key data."
                )
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 56,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 56,
                }
            ):
                self.message = (
                    self.message
                    + "Parameter error - Number_predicates, Attribute_ID or Cert_status."
                )
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 80,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 80,
                }
            ):
                self.message = (
                    self.message
                    + "Internal error while obtaining the key ring or z/OS® PKCS #11 token "
                    + "certificate information or record trust information."
                )
            case (
                {
                    "functionCode": 1,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 84,
                }
                | {
                    "functionCode": 2,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 84,
                }
                | {
                    "functionCode": 5,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 84,
                }
            ):
                self.message = (
                    self.message
                    + "The key ring profile for RACF_user_ID/Ring_name or z/OS PKCS #11 "
                    + "token is not found, or the virtual key ring user ID does not exist."
                )
            # CheckStatus Return and Reason Codes
            case (
                {
                    "functionCode": 4,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 60,
                }
            ):
                self.message = (
                    self.message + "Internal error - Unable to decode certificate."
                )
            case (
                {
                    "functionCode": 4,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 64,
                }
            ):
                self.message = (
                    self.message + "Certificate is registered with RACF as not trusted."
                )
            case (
                {
                    "functionCode": 4,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 68,
                }
            ):
                self.message = (
                    self.message
                    + "Parameter error - zero value specified for Certificate_length "
                    + "or Certificate_ptr."
                )
            # GetUpdateCode Return and Reason Codes
            case (
                {
                    "functionCode": 5,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 88,
                }
            ):
                self.message = (
                    self.message
                    + "Internal error - Unable to obtain the key ring or the z/OS PKCS "
                    + "#11 token data."
                )
            # IncSerialNum Return and Reason Codes
            case (
                {
                    "functionCode": 5,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 76,
                }
            ):
                self.message = self.message + "Certificate is invalid."
            case (
                {
                    "functionCode": 5,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 80,
                }
            ):
                self.message = (
                    self.message
                    + "Certificate is not installed or is marked NOTRUST, or does not "
                    + "have a private key."
                )
            case (
                {
                    "functionCode": 5,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 84,
                }
            ):
                self.message = (
                    self.message
                    + "Parameter error. A zero value was specified for one of the following "
                    + "parameters:\n * a certificate length or certificate owned by "
                    + "another user.\n * a minimum serial number."
                )
            # NewRing Return and Reason Codes
            case (
                {
                    "functionCode": 7,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
            ):
                self.message = (
                    self.message + "The profile for Ring_name is not found for REUSE."
                )
            case (
                {
                    "functionCode": 7,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
            ):
                self.message = (
                    self.message
                    + "The profile for Ring_name already exists. REUSE was not specified."
                )
            case (
                {
                    "functionCode": 7,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
            ):
                self.message = self.message + "The Ring_name is not valid."
            case (
                {
                    "functionCode": 7,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 44,
                }
            ):
                self.message = (
                    self.message + "The RACF_user_ID is not valid or not found."
                )
            # DataPut Return and Reason Codes
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 0,
                }
            ):
                self.message = (
                    self.message + "Success but the certificate's status is NOTRUST."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 4,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the DIGTCERT class needs to be refreshed to reflect the update."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 8,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the Label information is ignored because the certificate "
                    + "already exists in RACF."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 12,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the Label information is ignored because the certificate "
                    + "already exists in RACF, and its status is NOTRUST."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 16,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the Label information is ignored because the certificate "
                    + "already exists in RACF, and the DIGTCERT class needs to be refreshed "
                    + "to reflect the update."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
            ):
                self.message = (
                    self.message
                    + "Parameter error - incorrect value specified for Certificate_length "
                    + "or Certificate_ptr, or the label area is too small."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
            ):
                self.message = self.message + "Unable to decode the certificate."
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
            ):
                self.message = (
                    self.message
                    + "The private key is neither of a DER encoded format nor of a key "
                    + "label format."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 44,
                }
            ):
                self.message = (
                    self.message
                    + "Bad encoding of private key or unsupported algorithm or "
                    + "incorrect key size."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 48,
                }
            ):
                self.message = (
                    self.message
                    + "The specified private key does not match the existing private key."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 52,
                }
            ):
                self.message = self.message + "Cannot find the key label."
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 56,
                }
            ):
                self.message = (
                    self.message + "ICSF error when trying to find the key label."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 60,
                }
            ):
                self.message = self.message + "Not authorized to access ICSF key entry."
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 64,
                }
            ):
                self.message = (
                    self.message
                    + "The specified certificate label already exists in RACF."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 68,
                }
            ):
                self.message = (
                    self.message
                    + "The user ID specified by CERT_user_ID does not exist in RACF."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 76,
                }
            ):
                self.message = self.message + "The certificate cannot be installed."
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 80,
                }
            ):
                self.message = (
                    self.message + "The certificate exists under a different user."
                )
            case (
                {
                    "functionCode": 8,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 84,
                }
            ):
                self.message = self.message + "Cannot find the profile for Ring_name."
            # Data Remove Return and Reason Codes
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 0,
                }
            ):
                self.message = (
                    self.message
                    + "Success to remove the certificate from the ring but cannot delete "
                    + "the certificate from RACF because it is connected to other rings."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 4,
                }
            ):
                self.message = (
                    self.message
                    + "Success but cannot delete the certificate from RACF because of an "
                    + "unexpected error."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 8,
                }
            ):
                self.message = (
                    self.message
                    + "Success but cannot delete the certificate from RACF because of "
                    + "insufficient authority."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 12,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the DIGTCERT class needs to be refreshed to "
                    + "reflect the update."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 16,
                }
            ):
                self.message = (
                    self.message
                    + "Success to remove the certificate from the ring but cannot "
                    + "delete the certificate from RACF because it is has been used "
                    + "to generate a request."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
            ):
                self.message = (
                    self.message
                    + "Parameter error - incorrect value specified for Label_length, "
                    + "Label_ptr or CERT_user_ID."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
            ):
                self.message = (
                    self.message
                    + "Cannot find the certificate with the specified label and owner ID."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
            ):
                self.message = self.message + "The profile for Ring_name is not found."
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 44,
                }
            ):
                self.message = (
                    self.message
                    + "Cannot delete the certificate from RACF because it is connected "
                    + "to other rings."
                )
            case (
                {
                    "functionCode": 9,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 48,
                }
            ):
                self.message = (
                    self.message
                    + "Cannot delete the certificate from RACF because it is has been "
                    + "used to generate a request or its associated private key no longer "
                    + "exists in the PKDS or TKDS."
                )
            # DelRing Return and Reason Codes
            case (
                {
                    "functionCode": 10,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
            ):
                self.message = self.message + "The profile for Ring_name is not found."
            # DataRefresh Return and Reason Codes
            case (
                {
                    "functionCode": 11,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 0,
                }
            ):
                self.message = self.message + "The refresh is not needed."
            # DataAlter Return and Reason Codes
            case (
                {
                    "functionCode": 12,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 0,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the requested HIGHTRUST status is changed to TRUST since "
                    + "the certificate does not belong to CERTAUTH."
                )
            case (
                {
                    "functionCode": 12,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 4,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the DIGTCERT class needs to refresh to reflect the update."
                )
            case (
                {
                    "functionCode": 12,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 8,
                }
            ):
                self.message = (
                    self.message
                    + "There are more rings that satisfy the searching criteria, but can not be "
                    + "returned due to insufficient authority."
                )
            case (
                {
                    "functionCode": 4,
                    "safReturnCode": 8,
                    "racfReturnCode": 4,
                    "racfReasonCode": 8,
                }
            ):
                self.message = (
                    self.message
                    + "Success but the requested HIGHTRUST status is changed to TRUST since "
                    + "the certificate does not belong to CERTAUTH, and the DIGTCERT class "
                    + "needs to refresh to reflect the update."
                )
            case (
                {
                    "functionCode": 12,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
            ):
                self.message = (
                    self.message
                    + "Parameter error - invalid value specified for Label_length, Label_ptr, "
                    + "New_Label_length or New_Label_ptr."
                )
            case (
                {
                    "functionCode": 12,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
            ):
                self.message = self.message + "Certificate not found."
            case (
                {
                    "functionCode": 12,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
            ):
                self.message = (
                    self.message
                    + "New certificate label specified already exists in RACF for this user."
                )
            case (
                {
                    "functionCode": 12,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 44,
                }
            ):
                self.message = (
                    self.message
                    + "User ID specified by CERT_user_ID does not exist in RACF."
                )
            # GetRingInfo Return and Reason Codes
            case (
                {
                    "functionCode": 13,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 0,
                }
            ):
                self.message = self.message + "There are more rings to be returned."
            case (
                {
                    "functionCode": 13,
                    "safReturnCode": 4,
                    "racfReturnCode": 4,
                    "racfReasonCode": 8,
                }
            ):
                self.message = (
                    self.message
                    + "There are more rings that satisfy the searching criteria, but can "
                    + "not be returned due to insufficient authority."
                )
            case (
                {
                    "functionCode": 13,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 32,
                }
            ):
                self.message = self.message + "No ring found."
            case (
                {
                    "functionCode": 13,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 36,
                }
            ):
                self.message = (
                    self.message + "Parameter error - invalid value specified."
                )
            case (
                {
                    "functionCode": 13,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 40,
                }
            ):
                self.message = (
                    self.message
                    + "The output area is too small for 1 set of result. The Ring_result_length "
                    + "returned contains the amount of storage needed."
                )
            case (
                {
                    "functionCode": 13,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 44,
                }
            ):
                self.message = (
                    self.message
                    + "User ID specified by RACF_user_ID does not exist in RACF."
                )
            case (
                {
                    "functionCode": 13,
                    "safReturnCode": 8,
                    "racfReturnCode": 8,
                    "racfReasonCode": 48,
                }
            ):
                self.message = (
                    self.message
                    + "The ring specified as the search criteria for other rings is not found."
                )
            case _:
                self.message = (
                    self.message
                    + "Unknown Return and Reason Code combination. Please consult the RACF "
                    + "Callable Services manual here: "
                    + "https://www.ibm.com/docs/en/zos/3.1.0?topic=library-return-reason-codes."
                )
