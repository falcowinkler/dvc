from __future__ import unicode_literals

import os
import re
import getpass
import posixpath
import logging
import hashlib
from subprocess import Popen, PIPE

from dvc.config import Config
from dvc.scheme import Schemes

from dvc.remote.base import RemoteBASE, RemoteCmdError
from dvc.utils import fix_env, tmp_fname

logger = logging.getLogger(__name__)


class RemoteHDFS(RemoteBASE):
    scheme = Schemes.HDFS
    REGEX = r"^hdfs://((?P<user>.*)@)?.*$"
    PARAM_CHECKSUM = "checksum"

    def __init__(self, repo, config):
        super(RemoteHDFS, self).__init__(repo, config)
        url = config.get(Config.SECTION_REMOTE_URL, "/")
        self.path_info = self.path_cls(url)

        self.user = self.path_info.user
        if not self.user:
            self.user = config.get(
                Config.SECTION_REMOTE_USER, getpass.getuser()
            )

    def shell_command(self, cmd, user=None):
        # NOTE: close_fds doesn't work with redirected stdin/stdout/stderr.
        # See https://github.com/iterative/dvc/issues/1197.
        close_fds = os.name != "nt"

        executable = os.getenv("SHELL") if os.name != "nt" else None
        p = Popen(
            cmd,
            shell=True,
            close_fds=close_fds,
            executable=executable,
            env=fix_env(os.environ),
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
        )
        out, err = p.communicate()
        if p.returncode != 0:
            raise RemoteCmdError(self.scheme, cmd, p.returncode, err)
        return out.decode("utf-8")

    def hadoop_fs(self, cmd, user=None):
        cmd = "hadoop fs -" + cmd
        if user:
            cmd = "HADOOP_USER_NAME={} ".format(user) + cmd
        return self.shell_command(cmd)

    @staticmethod
    def _group(regex, s, gname):
        match = re.match(regex, s)
        assert match is not None
        return match.group(gname)

    def get_file_checksum(self, path_info):
        if self.is_dir(path_info):
            stdout = self.hadoop_fs(
                # get checksum recursively and ignore errors (e.g. for recursive directories)
                "ls -R {} | grep -oE '(\/.+?)' | xargs -I[] hadoop fs -checksum [] || true".format(path_info.path))
            return hashlib.md5(stdout.encode("utf-8")).hexdigest() + ".dir"
        regex = r".*\t.*\t(?P<checksum>.*)"
        stdout = self.hadoop_fs(
            "checksum {}".format(path_info.path), user=path_info.user
        )
        return self._group(regex, stdout, "checksum")

    def copy(self, from_info, to_info, **_kwargs):
        dname = posixpath.dirname(to_info.path)
        self.hadoop_fs("mkdir -p {}".format(dname), user=to_info.user)
        self.hadoop_fs(
            "cp -f {} {}".format(from_info.path, to_info.path),
            user=to_info.user,
        )

    def rm(self, path_info):
        self.hadoop_fs("rm -r -f {}".format(path_info.path), user=path_info.user)

    def remove(self, path_info):
        if path_info.scheme != "hdfs":
            raise NotImplementedError

        assert path_info.path

        logger.debug("Removing {}".format(path_info.path))

        self.rm(path_info)

    def exists(self, path_info):
        assert not isinstance(path_info, list)
        assert path_info.scheme == "hdfs"

        try:
            self.hadoop_fs("test -e {}".format(path_info.path))
            return True
        except RemoteCmdError:
            return False

    def is_dir(self, path_info):
        try:
            self.hadoop_fs("test -d {}".format(path_info.path))
            return True
        except RemoteCmdError:
            return False

    def _upload(self, from_file, to_info, **_kwargs):
        self.hadoop_fs(
            "mkdir -p {}".format(to_info.parent.url), user=to_info.user
        )

        tmp_file = tmp_fname(to_info.url)

        self.hadoop_fs(
            "copyFromLocal {} {}".format(from_file, tmp_file),
            user=to_info.user,
        )

        self.hadoop_fs(
            "mv {} {}".format(tmp_file, to_info.url), user=to_info.user
        )

    def _download(self, from_info, to_file, **_kwargs):
        self.hadoop_fs(
            "copyToLocal {} {}".format(from_info.url, to_file),
            user=from_info.user,
        )

    def list_cache_paths(self):
        try:
            self.hadoop_fs("test -e {}".format(self.path_info.url))
        except RemoteCmdError:
            return []

        stdout = self.hadoop_fs("ls -R {}".format(self.path_info.url))
        lines = stdout.split("\n")
        flist = []
        for line in lines:
            if not line.startswith("-"):
                continue
            flist.append(line.split()[-1])
        return flist
