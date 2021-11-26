from enum import IntEnum


class MasterPasswordStorageMethod(IntEnum):
    HASH = 1,
    HMAC = 2
