import subprocess

from typing import List
from karton.core import Karton, Task


def extract_strings(path: str, encoding: str = "s", n: int = 4) -> List:
    if encoding not in "sSbBlL":
        return []

    encoding_arg = "-e" + encoding
    minimum_size_arg = "-n" + str(n)

    strings_process = subprocess.run(
        ["strings", encoding_arg, minimum_size_arg, path], stdout=subprocess.PIPE
    )

    strings = strings_process.stdout.decode("utf-8").split("\n")

    return strings


class StringsExtractor(Karton):
    identity = "karton.strings_extractor"
    filters = [
        {
            "type": "sample",
            "stage": "recognized"
        }
    ]

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")

        with sample.download_temporary_file() as sample_file:
            path = sample_file.name

            ascii_strings = extract_strings(path)
            wide_strings = extract_strings(path, encoding="l")

            task = Task(
                {
                    "type": "feature",
                    "stage": "raw",
                    "kind": "strings",
                }
            )

            strings = ascii_strings + wide_strings

            task.add_payload("data", strings)
            task.add_payload("sha256", sample.sha256)

            self.send_task(task)

if __name__ == "__main__":
    StringsExtractor().loop()