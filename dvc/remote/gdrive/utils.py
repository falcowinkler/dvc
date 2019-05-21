import functools
import os
import threading

from dvc.progress import progress


class track_progress(object):
    def __init__(self, progress_name, fobj):
        self.progress_name = progress_name
        self.fobj = fobj
        self.file_size = os.fstat(fobj.fileno()).st_size

    def read(self, size):
        progress.update_target(
            self.progress_name, self.fobj.tell(), self.file_size
        )
        return self.fobj.read(size)

    def __getattr__(self, attr):
        return getattr(self.fobj, attr)


def only_once(func):
    lock = threading.Lock()
    locks = {}
    results = {}

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        key = (args, tuple(kwargs.items()))
        # could do with just setdefault, but it would require
        # create/delete a "default" Lock() object for each call, so it
        # is better to lock a single one for a short time
        with lock:
            if key not in locks:
                locks[key] = threading.Lock()
        with locks[key]:
            if key not in results:
                results[key] = func(*args, **kwargs)
        return results[key]

    return wrapped


if hasattr(os.stat_result, "st_blksize"):

    def get_chunk_size(f):
        return max(os.fstat(f.fileno()).st_blksize, 512)


else:

    def get_chunk_size(f):
        return 4096
