from __future__ import unicode_literals

from time import sleep
import posixpath
import os
import logging

try:
    import google_auth_oauthlib
    from .oauth2 import OAuth2
except ImportError:
    google_auth_oauthlib = None

from requests import ConnectionError

from dvc.scheme import Schemes
from dvc.path.gdrive import PathGDrive
from dvc.utils import tmp_fname, move
from dvc.utils.compat import urlparse, makedirs
from dvc.remote.base import RemoteBASE
from dvc.config import Config
from dvc.progress import progress
from dvc.remote.gdrive.utils import track_progress, only_once, get_chunk_size


logger = logging.getLogger(__name__)


class GDriveError(Exception):
    pass


class GDriveResourceNotFound(GDriveError):
    def __init__(self, path):
        super(GDriveResourceNotFound, self).__init__(
            "'{}' resource not found".format(path)
        )


class RemoteGDrive(RemoteBASE):
    """Google Drive remote implementation

    Example URLs:

    Datasets/my-dataset inside "My Drive" folder:

        gdrive://root/Datasets/my-dataset

    Folder by ID (recommended):

        gdrive://1r3UbnmS5B4-7YZPZmyqJuCxLVps1mASC

        (get it https://drive.google.com/drive/folders/{here})

    Dataset named "my-dataset" in the hidden application folder:

        gdrive://appDataFolder/my-dataset

        (this one wouldn't be visible through Google Drive web UI and
         couldn't be shared)
    """

    scheme = Schemes.GDRIVE
    REGEX = r"^gdrive://.*$"
    REQUIRES = {"google-auth-oauthlib": google_auth_oauthlib}
    PARAM_CHECKSUM = "md5Checksum"
    GOOGLEAPIS_BASE_URL = "https://www.googleapis.com/"
    MIME_GOOGLE_APPS_FOLDER = "application/vnd.google-apps.folder"
    SPACE_DRIVE = "drive"
    SCOPE_DRIVE = "https://www.googleapis.com/auth/drive"
    SPACE_APPDATA = "appDataFolder"
    SCOPE_APPDATA = "https://www.googleapis.com/auth/drive.appdata"
    TIMEOUT = (5, 60)

    # Default credential is needed to show the string of "Data Version
    # Control" in OAuth dialog application name and icon in authorized
    # applications list in Google account security settings. Also, the
    # quota usage is limited by the application defined by client_id.
    # The good practice would be to suggest the user to create their
    # own application credentials.
    DEFAULT_CREDENTIALPATH = os.path.join(
        os.path.dirname(__file__), "google-dvc-client-id.json"
    )

    def __init__(self, repo, config):

        super(RemoteGDrive, self).__init__(repo, config)

        self.url = config[Config.SECTION_REMOTE_URL].rstrip("/")

        parsed = urlparse(self.url)

        self.root = parsed.netloc

        if self.root == self.SPACE_APPDATA:
            default_scopes = self.SCOPE_APPDATA
            self.space = self.SPACE_APPDATA
        else:
            default_scopes = self.SCOPE_DRIVE
            self.space = self.SPACE_DRIVE

        credentialpath = config.get(
            Config.SECTION_GDRIVE_CREDENTIALPATH, self.DEFAULT_CREDENTIALPATH
        )
        scopes = config.get(Config.SECTION_GDRIVE_SCOPES, default_scopes)
        # scopes should be a list and it is space-delimited in all
        # configs, and `.split()` also works for a single-element list
        scopes = scopes.split()

        self.oauth2 = OAuth2(
            credentialpath,
            scopes,
            self.repo.config.config[Config.SECTION_OAUTH2],
        )

        self.prefix = parsed.path.strip("/")

        self.max_retries = 10

    @property
    def path_info(self):
        return PathGDrive(root=self.root)

    @property
    def session(self):
        """
        Security notice:

        It always adds the Authorization header to the requests, not
        paying attention is request is for googleapis.com or not. It is
        just how AuthorizedSession from google-auth implements
        adding its headers. Don't use this session to send requests to
        domains other than googleapis.com!
        """
        if not hasattr(self, "_session"):
            self._session = self.oauth2.get_session()
        return self._session

    def response_is_ratelimit(self, response):
        if response.status_code not in (403, 429):
            return False
        errors = response.json()["error"]["errors"]
        domains = [i["domain"] for i in errors]
        return "usageLimits" in domains

    def response_error_message(self, response):
        try:
            message = response.json()["error"]["message"]
        except Exception:
            message = response.text
        return "HTTP {}: {}".format(response.status_code, message)

    def request(self, method, path, *args, **kwargs):
        # Google Drive has tight rate limits, which strikes the
        # performance and gives the 403 and 429 errors.
        # See https://developers.google.com/drive/api/v3/handle-errors
        retries = 0
        exponential_backoff = 1
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.TIMEOUT
        while retries < self.max_retries:
            retries += 1
            response = self.session.request(
                method, self.GOOGLEAPIS_BASE_URL + path, *args, **kwargs
            )
            if (
                self.response_is_ratelimit(response)
                or response.status_code >= 500
            ):
                logger.debug(
                    "got {} response, will retry in {} sec".format(
                        response.status_code, exponential_backoff
                    )
                )
                sleep(exponential_backoff)
                exponential_backoff *= 2
            else:
                break
        if response.status_code >= 400:
            raise GDriveError(self.response_error_message(response))
        return response

    def get_metadata_by_id(self, file_id, **kwargs):
        return self.request(
            "GET", "drive/v3/files/" + file_id, **kwargs
        ).json()

    def search(self, parent=None, name=None, add_params={}):
        query = []
        if parent is not None:
            query.append("'{}' in parents".format(parent))
        if name is not None:
            query.append("name = '{}'".format(name))
        params = {"q": " and ".join(query), "spaces": self.space}
        params.update(add_params)
        while True:
            data = self.request("GET", "drive/v3/files", params=params).json()
            for i in data["files"]:
                yield i
            if not data.get("nextPageToken"):
                break
            params["pageToken"] = data["nextPageToken"]

    def get_metadata_by_path(self, root, path, fields=[]):
        parent = self.get_metadata_by_id(root)
        current_path = ["gdrive://" + parent["id"]]
        parts = path.split("/")
        # only specify fields for the last search query
        kwargs = [{}] * (len(parts) - 1) + [
            {"add_params": {"fields": "files({})".format(",".join(fields))}}
            if fields
            else {}
        ]
        for part, kwargs in zip(parts, kwargs):
            if not self.metadata_isdir(parent):
                raise GDriveError(
                    "{} is not a folder".format("/".join(current_path))
                )
            current_path.append(part)
            files = list(self.search(parent["id"], part, **kwargs))
            if len(files) > 1:
                raise GDriveError(
                    "path {} is duplicated".format("/".join(current_path))
                )
            elif len(files) == 0:
                raise GDriveResourceNotFound("/".join(current_path))
            parent = files[0]
        return parent

    def metadata_isdir(self, metadata):
        return metadata["mimeType"] == self.MIME_GOOGLE_APPS_FOLDER

    def get_file_checksum(self, path_info):
        metadata = self.get_metadata_by_path(
            path_info.root, path_info.path, params={"fields": "md5Checksum"}
        )
        return metadata["md5Checksum"]

    def _list_files(self, folder_id):
        for i in self.search(parent=folder_id):
            if self.metadata_isdir(i):
                for j in self._list_files(i["id"]):
                    yield i["name"] + "/" + j
            else:
                yield i["name"]

    def list_cache_paths(self):
        try:
            root = self.get_metadata_by_path(self.root, self.prefix)
        except GDriveResourceNotFound as e:
            logger.debug("list_cache_paths: {}".format(e))
        else:
            for i in self._list_files(root["id"]):
                yield self.prefix + "/" + i

    @only_once
    def mkdir(self, parent, name):
        data = {
            "name": name,
            "mimeType": self.MIME_GOOGLE_APPS_FOLDER,
            "parents": [parent],
            "spaces": self.space,
        }
        return self.request("POST", "drive/v3/files", json=data).json()

    @only_once
    def makedirs(self, parent, path):
        current_path = []
        for part in path.split("/"):
            current_path.append(part)
            try:
                metadata = self.get_metadata_by_path(parent, part)
                if not self.metadata_isdir(metadata):
                    raise GDriveError(
                        "{} is not a folder".format("/".join(current_path))
                    )
            except GDriveResourceNotFound:
                metadata = self.mkdir(parent, part)
            parent = metadata["id"]
        return parent

    def _resumable_upload_initiate(self, parent, filename):
        response = self.request(
            "POST",
            "upload/drive/v3/files",
            params={"uploadType": "resumable"},
            json={"name": filename, "space": self.space, "parents": [parent]},
        )
        return response.headers["Location"]

    def _resumable_upload_first_request(
        self, resumable_upload_url, from_file, to_info, file_size
    ):
        try:
            # outside of self.request() because this process
            # doesn't need it to handle errors and retries,
            # they are handled in the next "while" loop
            response = self.session.put(
                resumable_upload_url,
                data=from_file,
                headers={"Content-Length": str(file_size)},
                timeout=self.TIMEOUT,
            )
            return response.status_code in (200, 201)
        # XXX: which exceptions should be handled here?
        except ConnectionError:
            logger.info(
                "got connection error while uploading '{}/{}', "
                "will resume".format(self.url, to_info.path),
                exc_info=True,
            )
            return False

    def _resumable_upload_resume(
        self, resumable_upload_url, from_file, to_info, file_size
    ):
        try:
            # determine the offset
            response = self.session.put(
                resumable_upload_url,
                headers={
                    "Content-Length": str(0),
                    "Content-Range": "bytes */{}".format(file_size),
                },
                timeout=self.TIMEOUT,
            )
            if response.status_code in (200, 201):
                # file has been already uploaded
                return True
            elif response.status_code == 404:
                # restarting upload from the beginning wouldn't make a
                # profit, so it is better to notify the user
                raise GDriveError("resumable upload URL has been expired")
            elif response.status_code != 308:
                logger.error(
                    "upload resume failure: {}".format(
                        self.response_error_message(response)
                    )
                )
                return False
            # response.status_code is 308 (Resume Incomplete) - continue
            if "Range" in response.headers:
                # if Range header contains a string "bytes 0-9/20"
                # then the server has received the bytes from 0 to 9
                # (including the ends), so upload should be resumed from
                # byte 10
                offset = int(response.headers["Range"].split("-")[-1]) + 1
            else:
                # there could be no Range header in the server response,
                # then upload should be resumed from start
                offset = 0
            logger.debug(
                "resuming {} upload from offset {}".format(
                    to_info.path, offset
                )
            )
            # resume the upload
            from_file.seek(offset, 0)
            response = self.session.put(
                resumable_upload_url,
                data=from_file,
                headers={
                    "Content-Length": str(file_size - offset),
                    "Content-Range": "bytes {}-{}/{}".format(
                        offset, file_size - 1, file_size
                    ),
                },
                timeout=self.TIMEOUT,
            )
            return response.status_code in (200, 201)
        except ConnectionError:
            # don't overload the CPU on consistent network failure
            sleep(1.0)
            # XXX: should we add some break condition and raise exception?
            return False

    def upload_file(self, from_info, to_info, progress_name):
        """Implements resumable upload protocol

        https://developers.google.com/drive/api/v3/manage-uploads#resumable
        """

        dirname = posixpath.dirname(to_info.path).strip("/")
        if dirname:
            parent = self.makedirs(to_info.root, dirname)
        else:
            parent = to_info.root

        # initiate resumable upload
        resumable_upload_url = self._resumable_upload_initiate(
            parent, posixpath.basename(to_info.path)
        )

        from_file = open(from_info.path, "rb")
        if progress_name is not None:
            from_file = track_progress(progress_name, from_file)

        file_size = os.fstat(from_file.fileno()).st_size

        success = self._resumable_upload_first_request(
            resumable_upload_url, from_file, to_info, file_size
        )
        while not success:
            success = self._resumable_upload_resume(
                resumable_upload_url, from_file, to_info, file_size
            )

    def upload(self, from_infos, to_infos, names=None, no_progress_bar=False):

        names = self._verify_path_args(to_infos, from_infos, names)

        for from_info, to_info, name in zip(from_infos, to_infos, names):

            if from_info.scheme != Schemes.LOCAL:
                raise NotImplementedError

            if to_info.scheme != self.scheme:
                raise NotImplementedError

            logger.debug(
                "Uploading '{}' to '{}/{}'".format(
                    from_info.path, self.url, to_info.path
                )
            )

            if not name:
                name = os.path.basename(from_info.path)

            if not no_progress_bar:
                progress.update_target(name, 0, None)

            try:
                self.upload_file(
                    from_info,
                    to_info,
                    progress_name=name if no_progress_bar is False else None,
                )
            except Exception:
                msg = "failed to upload '{}' to '{}/{}'"
                logger.exception(
                    msg.format(from_info.path, self.url, to_info.path)
                )
                continue

            progress.finish_target(name)

    def download_file(self, from_info, to_info, progress_name=None):
        metadata = self.get_metadata_by_path(
            from_info.root, from_info.path, fields=["id", "mimeType", "size"]
        )
        response = self.request(
            "GET",
            "drive/v3/files/" + metadata["id"],
            params={"alt": "media"},
            stream=True,
        )
        current = 0
        if response.status_code != 200:
            try:
                message = response.json()["error"]["message"]
            except Exception:
                message = response.text
            raise GDriveError(
                "HTTP {}: {}".format(response.status_code, message)
            )
        makedirs(os.path.dirname(to_info.path), exist_ok=True)
        tmp_file = tmp_fname(to_info.path)
        with open(tmp_file, "wb") as f:
            chunk_size = get_chunk_size(f)
            for chunk in response.iter_content(chunk_size):
                f.write(chunk)
                if progress_name is not None:
                    current += len(chunk)
                    progress.update_target(
                        progress_name, current, metadata["size"]
                    )
        move(tmp_file, to_info.path)

    def download(
        self,
        from_infos,
        to_infos,
        no_progress_bar=False,
        names=None,
        resume=False,
    ):

        names = self._verify_path_args(from_infos, to_infos, names)

        for to_info, from_info, name in zip(to_infos, from_infos, names):

            if from_info.scheme != self.scheme:
                raise NotImplementedError

            if to_info.scheme != Schemes.LOCAL:
                raise NotImplementedError

            msg = "Downloading '{}/{}' to '{}'".format(
                from_info.root, from_info.path, to_info.path
            )
            logger.debug(msg)

            if not name:
                name = os.path.basename(to_info.path)

            if not no_progress_bar:
                progress.update_target(name, 0, None)

            try:
                self.download_file(from_info, to_info, progress_name=name)
            except Exception:
                msg = "failed to download '{}/{}' to '{}'"
                logger.exception(
                    msg.format(from_info.root, from_info.path, to_info.path)
                )
                continue

            if not no_progress_bar:
                progress.finish_target(name)
