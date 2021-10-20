from enum import Enum


class MasterPasswordStorageMethod(Enum):
    HASH = 1,
    HMAC = 2
