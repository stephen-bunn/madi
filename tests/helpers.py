import random
import string
from contextlib import contextmanager
from os import PathLike
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Generator


@contextmanager
def temp_dirpath(dir: PathLike[str] | None = None) -> Generator[Path, None, None]:
    with TemporaryDirectory(
        dir=dir,
        prefix="madi-test-"
        + ("" if dir is not None else "".join(random.choices(string.digits, k=16)) + "-"),
    ) as tmpdir:
        yield Path(tmpdir)
