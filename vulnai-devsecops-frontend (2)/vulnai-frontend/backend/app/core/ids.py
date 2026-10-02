import secrets


class ObjectId(str):
    def __new__(cls, value: str | None = None):
        value = value or secrets.token_hex(12)
        if len(value) != 24 or any(char not in "0123456789abcdefABCDEF" for char in value):
            raise ValueError("Invalid ID")
        return super().__new__(cls, value.lower())