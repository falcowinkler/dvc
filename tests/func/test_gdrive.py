from subprocess import check_call
import shutil
import os
import tempfile

import pytest

from dvc.main import main
from dvc.config import Config
from dvc.remote.gdrive import RemoteGDrive


oauth2_storage = os.path.join(
    Config.get_global_config_dir(),
    "gdrive-oauth2",
    "81562e04895c64d8c65a45710a0a8a6b",
)
if not os.path.exists(oauth2_storage):
    pytest.skip(
        "skipping GDrive tests: could decrypt access token only in Travis",
        allow_module_level=True,
    )


def _run_test(repo_dir, dvc_repo, base_url):
    dirname = tempfile.mktemp("", "dvc_test_", "")
    url = base_url + dirname
    files = [repo_dir.FOO, repo_dir.DATA_SUB.split(os.path.sep)[0]]

    gdrive = RemoteGDrive(dvc_repo, {"url": url})

    # push files
    check_call(["dvc", "add"] + files)
    check_call(["dvc", "remote", "add", "gdrive", url])
    assert main(["push", "-r", "gdrive"]) == 0

    paths = dvc_repo.cache.local.list_cache_paths()
    paths = [i.split(os.path.sep)[-2:] for i in paths]

    # check that files are correctly uploaded
    testdir = gdrive.get_metadata_by_path(gdrive.root, gdrive.prefix)
    q = "'{}' in parents".format(testdir["id"])
    found = list(gdrive.search(add_params={"q": q}))
    assert set(i["name"] for i in found) == set([i[0] for i in paths])
    q = " or ".join("'{}' in parents".format(i["id"]) for i in found)
    found = list(gdrive.search(add_params={"q": q}))
    assert set(i["name"] for i in found) == set(i[1] for i in paths)

    # remove cache and files
    shutil.rmtree(".dvc/cache")
    for i in files:
        if os.path.isdir(i):
            shutil.rmtree(i)
        else:
            os.remove(i)

    # check that they are in list_cache_paths
    assert set(gdrive.list_cache_paths()) == {
        "/".join([dirname] + i) for i in paths
    }

    # pull them back from remote
    assert main(["pull", "-r", "gdrive"]) == 0

    assert set(files) < set(os.listdir("."))

    # remove the temporary directory on Google Drive
    resp = gdrive.request("DELETE", "drive/v3/files/" + testdir["id"])
    print("Delete temp dir: HTTP {}".format(resp.status_code))


def test_gdrive_push_pull(repo_dir, dvc_repo):
    _run_test(repo_dir, dvc_repo, "gdrive://root/")


def test_gdrive_push_pull_appfolder(repo_dir, dvc_repo):
    _run_test(repo_dir, dvc_repo, "gdrive://appDataFolder/")
