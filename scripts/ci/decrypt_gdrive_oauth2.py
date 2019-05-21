from subprocess import check_call
import os
import sys

from dvc.config import Config

OAUTH2_TOKEN_FILE_KEY = os.getenv("OAUTH2_TOKEN_FILE_KEY")
OAUTH2_TOKEN_FILE_IV = os.getenv("OAUTH2_TOKEN_FILE_IV")
if OAUTH2_TOKEN_FILE_KEY is None or OAUTH2_TOKEN_FILE_IV is None:
    print("{}:".format(sys.argv[0]))
    print("OAUTH2_TOKEN_FILE_KEY or OAUTH2_TOKEN_FILE_IV are not defined.")
    print("Skipping decrypt.")
    sys.exit(0)

src = os.path.join("scripts", "ci", "gdrive-oauth2")
dest = os.path.join(Config.get_global_config_dir(), "gdrive-oauth2")
if not os.path.exists(dest):
    os.makedirs(dest)

KEYS = ["81562e04895c64d8c65a45710a0a8a6b", "160f0daf067a7511bd8b8e3b35e3a8bd"]

for i in KEYS:
    print("Decrypting", i)
    check_call(
        [
            "openssl",
            "aes-256-cbc",
            "-d",
            "-K",
            OAUTH2_TOKEN_FILE_KEY,
            "-iv",
            OAUTH2_TOKEN_FILE_IV,
            "-in",
            os.path.join(src, i + ".enc"),
            "-out",
            os.path.join(dest, i),
        ]
    )
    print("Done")
