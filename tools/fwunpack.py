#!/usr/bin/env python3
"""Decrypt a ReyeeOS firmware container and write out its rootfs squashfs.

    python3 -I fwunpack.py <container|vendor .zip> <out.squashfs>

Container formats (firmware-audit.md §3.14, §11):
  v1  'upgrade_crypt_v1!@2021' (22 B) + data XOR 0x7f; the header overwrote the
      tar's first 6 bytes, which are 'sysupg'.
  v2  'upgrade_crypt_v2!@2023\\n' + base64(OpenSSL 'Salted__' AES-256-CBC),
      key/iv = EVP_BytesToKey(MD5, salt, FW_KEY, iter=2023).
A decrypted payload is a tar (sysupgrade: CONTROL/kernel/root) or a raw image.
Tars are searched recursively: an inner container is decrypted in turn, a
member named root/rootfs* is taken, and otherwise the first 'hsqs' squashfs is
carved out by its superblock's bytes_used.
"""
import base64
import hashlib
import io
import struct
import sys
import tarfile
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FW_KEY = b"BR0khBR0khsHi4MkNGrJ421Yf&j8ceh6"   # firmware-audit.md §11
V1 = b"upgrade_crypt_v1!@2021"
V2 = b"upgrade_crypt_v2!@2023"


def evp_bytes_to_key(pw, salt, n, klen=32, ivlen=16):
    out, prev = b"", b""
    while len(out) < klen + ivlen:
        d = prev + pw + salt
        for _ in range(n):
            d = hashlib.md5(d).digest()
        prev = d
        out += d
    return out[:klen], out[klen:klen + ivlen]


def decrypt(b):
    if b.startswith(V1):
        body = bytes(x ^ 0x7F for x in b[len(V1):])
        return b"sysupg" + body[6:] if len(body) > 6 else body
    if b.startswith(V2):
        blob = base64.b64decode(b[len(V2):].strip())
        if blob[:8] != b"Salted__":
            raise ValueError("v2 payload is not OpenSSL Salted__")
        key, iv = evp_bytes_to_key(FW_KEY, blob[8:16], 2023)
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = d.update(blob[16:]) + d.finalize()
        return pt[:-pt[-1]]
    return None


def carve_squashfs(b):
    i = b.find(b"hsqs")
    while i >= 0:
        if len(b) >= i + 96:
            used = struct.unpack_from("<Q", b, i + 40)[0]
            if 96 < used <= len(b) - i:
                return b[i:i + used]
        i = b.find(b"hsqs", i + 1)
    return None


def find_rootfs(b, depth=0):
    if depth > 4:
        return None
    dec = decrypt(b)
    if dec is not None:
        return find_rootfs(dec, depth + 1)
    try:
        tf = tarfile.open(fileobj=io.BytesIO(b))
        members = [m for m in tf.getmembers() if m.isfile()]
    except tarfile.TarError:
        members = None
    if members:
        named = [m for m in members if m.name.split("/")[-1].startswith(("root", "rootfs"))]
        for m in named + [m for m in members if m not in named]:
            data = tf.extractfile(m).read()
            if data.startswith(b"hsqs"):
                return data
            r = find_rootfs(data, depth + 1)
            if r:
                return r
        return None
    return carve_squashfs(b)


def main():
    src, out = sys.argv[1], sys.argv[2]
    if src.endswith(".zip"):
        z = zipfile.ZipFile(src)
        inner = [n for n in z.namelist() if "encrypto" in n or n.endswith((".bin", ".tar.gz"))]
        if not inner:
            sys.exit("no firmware container in zip")
        b = z.read(inner[0])
        print("container:", inner[0].split("/")[-1])
    else:
        b = open(src, "rb").read()
    fs = find_rootfs(b)
    if not fs:
        sys.exit("no squashfs found")
    open(out, "wb").write(fs)
    print(f"{out}: {len(fs)} bytes sha256 {hashlib.sha256(fs).hexdigest()}")


if __name__ == "__main__":
    main()
