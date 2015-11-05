import os
import stat

import elf


class ELFFile(object):
    def __init__(self, path=None):
        self.header = None
        self.path = path

        if path:
            self.read(path)

    def read(self, path):
        with open(path) as f:
            data = bytearray(f.read())

        self.bits = bits = elf.decode_bits(data)
        self.header = elf.ElfN_Ehdr.decode(data, bits)

    def save(self, path=None):
        path = path or self.path
        assert path

        with open(path, 'w') as f:
            self.write(f)

        rwxrwxr_x = stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH
        os.chmod(path, rwxrwxr_x)

    def write(self, f):
        pass


if __name__ == '__main__':
    f = ELFFile('test')
    f.header.dump()
