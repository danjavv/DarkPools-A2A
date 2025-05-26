# Code to generate json files for financial data sharings

## Sharing encodings:

* Strings:
    * Boolean sharing is done. 
    * Each byte is encoded using 'iso-8859-1' format, as 'utf-8' was not able to encode every possible byte. 
    * After encoding, the sharing is done, as per the usual boolean sharing scheme. 
    * The obtained shares are then converted to hexadecimal strings and stored in the files as follows: `"t{space}s"`.

* Numbers (Arithmetically significant numbers)
    * Arithmetic sharing is done. 
    * A list of these columns are present in the `json_create.py` file.
    * The `FIELD_POWER` and the `DECIMAL_PRECISION` is initialized in the `json_create.py` file.
    * The plaintext number is converted to float from string, multiplied with `2**DECIMAL_PRECISION`, and converted to integer.
    * Then the sharing is done as usual, in the modulus of `2**FIELD_POWER`.
    * The obtained shares are then onverted to hexadecimal strings of length 16 and the files as follows: `"t{space}s"`.