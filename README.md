# dnparser
Grab helpful details from .NET executables for YARA rules

Work in progress so it will probably break a lot.

## Usage

`python parser_main.py <file>`

## Sample Output

```
-------------------------------------------------------------------------------------
                                  Locating Metadata

CLR header RVA: 0X2008
Metadata header RVA: 0X23B0
Metadata size: 0X1858
Metadata magic bytes:
   - Hex: 42534a42
   - ASCII: BSJB
-------------------------------------------------------------------------------------
                                       STREAMS

Stream               Size                 RVA                  Physical Address
#~                   0X6E8                0X241C               0X61C
#Strings             0X7C4                0X2B04               0XD04
#US                  0X5EC                0X32C8               0X14C8
#GUID                0X10                 0X38B4               0X1AB4
#Blob                0X344                0X38C4               0X1AC4
-------------------------------------------------------------------------------------
                                  Assembly Details

Name: UAC
Version: 1.0.0.0
Version Hex: 0100000000000000
-------------------------------------------------------------------------------------
                                     Module Name

UAC.dll
-------------------------------------------------------------------------------------
                                        MVID

Hex                                      UUID
8a2caf7a84918c47b5bf5415b683eb30         7aaf2c8a-9184-478c-b5bf-5415b683eb30
-------------------------------------------------------------------------------------
                                     TypeLib ID

21373474-dfe8-4e53-8c9b-28c21d6efea1
-------------------------------------------------------------------------------------
                               Notable Irregularities

-------------------------------------------------------------------------------------
                                      YARA Tips

*  .NET binaries should have 5 standard streams. Any extra or missing?

*  Assembly name and Module name are in the #Strings stream,
   so they make good strings in rules.

*  Unique Assembly version? Use the hex output.

*  MVID is the module version ID. This changes with recompilation,
   but can track a sample that has been repacked/modified.
   This is in the #GUID stream so use the hex output.

*  TypeLib ID is unique per project and robust against recompilation.
   This is in plaintext, use the string value.
   NOTE: The fullword modifier will fail here since the value is prepended
   by its length: 0x24 ($ in ASCII)
-------------------------------------------------------------------------------------
```
