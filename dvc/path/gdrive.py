from dvc.scheme import Schemes
from .base import PathBASE


class PathGDrive(PathBASE):
    scheme = Schemes.GDRIVE

    def __init__(self, root, url=None, path=None):
        super(PathGDrive, self).__init__(url, path)
        self.root = root
