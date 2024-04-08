
class Client:
    def __init__(self, cid: bytes, name: str, last_seen: str, pass_hash: bytes):
        self.cid = cid
        self.name = name
        self.last_seen = last_seen
        self.pass_hash = pass_hash
        self.aes = ''
        self.nonce = ''
