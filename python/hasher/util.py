import mmap
from pathlib import Path
from types import TracebackType

from typing_extensions import Self

import hasher

__author__ = "juckelman"


class ReadOnlyMmappedFile(object):
    def __init__(self, path: Path | str):
        self.file = None
        self.buf = None

        self.file = open(path, "rb")  # pylint: disable=consider-using-with
        try:
            self.buf = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        except:
            self.file.close()
            raise

    def close(self) -> None:
        try:
            if self.buf:
                self.buf.close()
                self.buf = None
        finally:
            if self.file:
                self.file.close()
                self.file = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


class MmappedHSet(object):
    def __init__(self, path: Path | str):
        self.hset = None
        self.mfile = None

        self.mfile = ReadOnlyMmappedFile(path)
        try:
            self.hset = hasher.HSet.load(self.mfile.buf)
        except:
            self.mfile.close()
            raise

    def close(self) -> None:
        try:
            if self.hset:
                self.hset.destroy()
                self.hset = None
        finally:
            if self.mfile:
                self.mfile.close()
                self.mfile = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()
