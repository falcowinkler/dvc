from datetime import datetime, timedelta
import json

import mock

import pytest

import requests

import google.oauth2.credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from dvc.remote.gdrive import RemoteGDrive, GDriveError, GDriveResourceNotFound
from dvc.remote.gdrive.oauth2 import OAuth2
from dvc.path.gdrive import PathGDrive
from dvc.repo import Repo


GDRIVE_URL = "gdrive://root/data"
GDRIVE_APPFOLDER_URL = "gdrive://appDataFolder/data"
AUTHORIZATION = {"authorization": "Bearer MOCK_token"}
FOLDER = {"mimeType": RemoteGDrive.MIME_GOOGLE_APPS_FOLDER}
FILE = {"mimeType": "not-a-folder"}

COMMON_KWARGS = {
    "data": None,
    "headers": AUTHORIZATION,
    "timeout": RemoteGDrive.TIMEOUT,
}


class Response:
    def __init__(self, data, status_code=200):
        self._data = data
        self.text = json.dumps(data) if isinstance(data, dict) else data
        self.status_code = status_code

    def json(self):
        return self._data


@pytest.fixture()
def repo():
    return Repo(".")


@pytest.fixture
def gdrive(repo):
    gdrive = RemoteGDrive(repo, {"url": GDRIVE_URL})
    return gdrive


@pytest.fixture
def gdrive_appfolder(repo):
    gdrive = RemoteGDrive(repo, {"url": GDRIVE_APPFOLDER_URL})
    return gdrive


@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    req_mock = mock.Mock(return_value=Response("test"))
    monkeypatch.setattr("requests.sessions.Session.request", req_mock)
    return req_mock


def _url(url):
    return RemoteGDrive.GOOGLEAPIS_BASE_URL + url


@pytest.fixture(autouse=True)
def fake_creds(monkeypatch):

    creds = google.oauth2.credentials.Credentials(
        token="MOCK_token",
        refresh_token="MOCK_refresh_token",
        token_uri="MOCK_token_uri",
        client_id="MOCK_client_id",
        client_secret="MOCK_client_secret",
        scopes=["MOCK_scopes"],
    )
    creds.expiry = datetime.now() + timedelta(days=1)

    mocked_flow = mock.Mock()
    mocked_flow.run_console.return_value = creds
    mocked_flow.run_local_server.return_value = creds

    monkeypatch.setattr(
        InstalledAppFlow,
        "from_client_secrets_file",
        classmethod(lambda *args, **kwargs: mocked_flow),
    )

    monkeypatch.setattr(
        OAuth2, "_get_creds_id", mock.Mock(return_value="test")
    )


@pytest.fixture(autouse=True)
def no_refresh(monkeypatch):
    refresh_mock = mock.Mock()
    monkeypatch.setattr(
        "google.oauth2.credentials.Credentials.refresh", refresh_mock
    )
    return refresh_mock


@pytest.fixture()
def makedirs(monkeypatch):
    mocked = mock.Mock(return_value="FOLDER_ID")
    monkeypatch.setattr(RemoteGDrive, "makedirs", mocked)
    return mocked


def test_init_drive(gdrive):
    assert gdrive.root == "root"
    assert gdrive.url == GDRIVE_URL
    assert gdrive.oauth2.scopes == ["https://www.googleapis.com/auth/drive"]
    assert gdrive.space == RemoteGDrive.SPACE_DRIVE


def test_init_appfolder(gdrive_appfolder):
    assert gdrive_appfolder.root == RemoteGDrive.SPACE_APPDATA
    assert gdrive_appfolder.url == GDRIVE_APPFOLDER_URL
    assert gdrive_appfolder.oauth2.scopes == [
        "https://www.googleapis.com/auth/drive.appdata"
    ]
    assert gdrive_appfolder.space == RemoteGDrive.SPACE_APPDATA


def test_init_folder_id(repo):
    url = "gdrive://FOLDER_ID/data"
    remote = RemoteGDrive(repo, {"url": url})
    assert remote.root == "FOLDER_ID"
    assert remote.url == url
    assert remote.oauth2.scopes == ["https://www.googleapis.com/auth/drive"]
    assert remote.space == "drive"


def test_path_info(repo):
    remote = RemoteGDrive(repo, {"url": "gdrive://root"})
    assert remote.path_info.root == "root"


def test_get_session(gdrive, no_requests):
    session = gdrive.oauth2.get_session()
    session.get("http://httpbin.org/get")
    args, kwargs = no_requests.call_args
    assert kwargs["headers"]["authorization"] == AUTHORIZATION["authorization"]


def test_response_is_ratelimit(gdrive):
    assert gdrive.response_is_ratelimit(
        Response({"error": {"errors": [{"domain": "usageLimits"}]}}, 403)
    )
    assert not gdrive.response_is_ratelimit(Response(""))


def test_response_error_message(gdrive):
    r = Response({"error": {"message": "test"}})
    assert gdrive.response_error_message(r) == "HTTP 200: test"
    r = Response("test")
    assert gdrive.response_error_message(r) == "HTTP 200: test"


def test_request(gdrive, no_requests):
    assert gdrive.request("GET", "test").text == "test"
    no_requests.assert_called_once_with("GET", _url("test"), **COMMON_KWARGS)


def test_request_refresh(gdrive, no_requests, no_refresh):
    no_requests.side_effect = [
        Response("error", 401),
        Response("after_refresh", 200),
    ]
    assert gdrive.request("GET", "test").text == "after_refresh"
    no_refresh.assert_called_once()
    assert no_requests.mock_calls == [
        mock.call("GET", _url("test"), **COMMON_KWARGS),
        mock.call("GET", _url("test"), **COMMON_KWARGS),
    ]


def test_request_retry_and_backoff(gdrive, no_requests, monkeypatch):
    no_requests.side_effect = [
        Response("error", 500),
        Response("error", 500),
        Response("retry", 200),
    ]
    sleep_mock = mock.Mock()
    monkeypatch.setattr("dvc.remote.gdrive.sleep", sleep_mock)
    assert gdrive.request("GET", "test").text == "retry"
    assert no_requests.mock_calls == [
        mock.call("GET", _url("test"), **COMMON_KWARGS),
        mock.call("GET", _url("test"), **COMMON_KWARGS),
        mock.call("GET", _url("test"), **COMMON_KWARGS),
    ]
    assert sleep_mock.mock_calls == [mock.call(1), mock.call(2)]


def test_request_4xx(gdrive, no_requests):
    no_requests.return_value = Response("error", 400)
    with pytest.raises(GDriveError):
        gdrive.request("GET", "test")


def test_get_metadata_by_id(gdrive, no_requests):
    gdrive.get_metadata_by_id("test")
    no_requests.assert_called_once_with(
        "GET", _url("drive/v3/files/test"), **COMMON_KWARGS
    )


def test_search(gdrive, no_requests):
    no_requests.side_effect = [
        Response({"files": ["test1"], "nextPageToken": "TEST_nextPageToken"}),
        Response({"files": ["test2"]}),
    ]
    assert list(gdrive.search("test", "root")) == ["test1", "test2"]


def test_metadata_by_path(gdrive, no_requests, monkeypatch):
    no_requests.side_effect = [
        Response(dict(id="root", name="root", **FOLDER)),
        Response({"files": [dict(id="id1", name="path1", **FOLDER)]}),
        Response({"files": [dict(id="id2", name="path2", **FOLDER)]}),
    ]
    gdrive.get_metadata_by_path("root", "path1/path2", ["field1", "field2"])
    assert no_requests.mock_calls == [
        mock.call("GET", _url("drive/v3/files/root"), **COMMON_KWARGS),
        mock.call(
            "GET",
            _url("drive/v3/files"),
            params={
                "q": "'root' in parents and name = 'path1'",
                "spaces": "drive",
            },
            **COMMON_KWARGS
        ),
        mock.call(
            "GET",
            _url("drive/v3/files"),
            params={
                "q": "'id1' in parents and name = 'path2'",
                "spaces": "drive",
                "fields": "files(field1,field2)",
            },
            **COMMON_KWARGS
        ),
    ]


def test_metadata_by_path_not_a_folder(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_id",
        mock.Mock(return_value=dict(id="id1", name="root", **FOLDER)),
    )
    monkeypatch.setattr(
        gdrive,
        "search",
        mock.Mock(return_value=[dict(id="id2", name="path1", **FILE)]),
    )
    with pytest.raises(GDriveError):
        gdrive.get_metadata_by_path(
            "root", "path1/path2", ["field1", "field2"]
        )
    gdrive.get_metadata_by_path("root", "path1", ["field1", "field2"])


def test_metadata_by_path_duplicate(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_id",
        mock.Mock(return_value=dict(id="id1", name="root", **FOLDER)),
    )
    monkeypatch.setattr(
        gdrive,
        "search",
        mock.Mock(
            return_value=[
                dict(id="id2", name="path1", **FOLDER),
                dict(id="id3", name="path1", **FOLDER),
            ]
        ),
    )
    with pytest.raises(GDriveError):
        gdrive.get_metadata_by_path(
            "root", "path1/path2", ["field1", "field2"]
        )


def test_metadata_by_path_not_found(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_id",
        mock.Mock(return_value=dict(id="root", name="root", **FOLDER)),
    )
    monkeypatch.setattr(gdrive, "search", mock.Mock(return_value=[]))
    with pytest.raises(GDriveResourceNotFound):
        gdrive.get_metadata_by_path(
            "root", "path1/path2", ["field1", "field2"]
        )


def test_get_file_checksum(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_path",
        mock.Mock(
            return_value=dict(id="id1", name="path1", md5Checksum="checksum")
        ),
    )
    checksum = gdrive.get_file_checksum(PathGDrive(gdrive.root, path="path1"))
    assert checksum == "checksum"
    gdrive.get_metadata_by_path.assert_called_once_with(
        gdrive.root, "path1", params={"fields": "md5Checksum"}
    )


def test_list_cache_paths(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_path",
        mock.Mock(return_value=dict(id="root", name="root", **FOLDER)),
    )
    files_lists = [
        [dict(id="f1", name="f1", **FOLDER), dict(id="f2", name="f2", **FILE)],
        [dict(id="f3", name="f3", **FILE)],
    ]
    monkeypatch.setattr(gdrive, "search", mock.Mock(side_effect=files_lists))
    assert list(gdrive.list_cache_paths()) == ["data/f1/f3", "data/f2"]
    gdrive.get_metadata_by_path.assert_called_once_with("root", "data")


def test_list_cache_path_not_found(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_path",
        mock.Mock(side_effect=GDriveResourceNotFound("test")),
    )
    assert list(gdrive.list_cache_paths()) == []
    gdrive.get_metadata_by_path.assert_called_once_with("root", "data")


def test_mkdir(gdrive, no_requests):
    no_requests.return_value = Response("test")
    assert gdrive.mkdir("root", "test") == "test"
    no_requests.assert_called_once_with(
        "POST",
        _url("drive/v3/files"),
        json={
            "name": "test",
            "mimeType": FOLDER["mimeType"],
            "parents": ["root"],
            "spaces": "drive",
        },
        **COMMON_KWARGS
    )


def test_makedirs(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_path",
        mock.Mock(
            side_effect=[
                dict(id="id1", name="test1", **FOLDER),
                GDriveResourceNotFound("test1/test2"),
            ]
        ),
    )
    monkeypatch.setattr(
        gdrive, "mkdir", mock.Mock(side_effect=[{"id": "id2"}])
    )
    assert gdrive.makedirs(gdrive.root, "test1/test2") == "id2"
    assert gdrive.get_metadata_by_path.mock_calls == [
        mock.call(gdrive.root, "test1"),
        mock.call("id1", "test2"),
    ]
    assert gdrive.mkdir.mock_calls == [mock.call("id1", "test2")]


def test_makedirs_error(gdrive, monkeypatch):
    monkeypatch.setattr(
        gdrive,
        "get_metadata_by_path",
        mock.Mock(side_effect=[dict(id="id1", name="test1", **FILE)]),
    )
    with pytest.raises(GDriveError):
        gdrive.makedirs(gdrive.root, "test1/test2")


def test_resumable_upload_first_request(gdrive, no_requests):
    resp = Response("", 201)
    no_requests.return_value = resp
    from_file = mock.Mock()
    to_info = mock.Mock()
    assert (
        gdrive._resumable_upload_first_request("url", from_file, to_info, 100)
        is True
    )


def test_resumable_upload_first_request_connection_error(gdrive, no_requests):
    no_requests.side_effect = requests.ConnectionError
    from_file = mock.Mock()
    to_info = mock.Mock()
    assert (
        gdrive._resumable_upload_first_request("url", from_file, to_info, 100)
        is False
    )


def test_resumable_upload_first_request_failure(gdrive, no_requests):
    no_requests.return_value = Response("", 400)
    from_file = mock.Mock()
    to_info = mock.Mock()
    assert (
        gdrive._resumable_upload_first_request("url", from_file, to_info, 100)
        is False
    )
