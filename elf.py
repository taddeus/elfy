import struct
import inspect


class Encodable(object):
    fields = ()

    def __init__(self):
        for field in self.fields:
            setattr(self, field, None)

    @classmethod
    def fmt(cls, bits):
        idx = 1 if bits == 64 else 0
        return '<' + ' '.join(s[idx] for s, _ in cls.fields)

    @classmethod
    def decode(cls, data, bits):
        fmt = cls.fmt(bits)
        parts = struct.unpack(fmt, data[:struct.calcsize(fmt)])
        obj = cls()

        for (_, field), value in zip(cls.fields, parts):
            setattr(obj, field, value)

        return obj

    def encode(self, bits):
        args = [getattr(self, field) for (_, field) in self.fields]
        return struct.pack(self.fmt(bits), *args)

    def dump(self):
        print '%s:' % self.__class__.__name__

        for s, field in self.fields:
            print '%-15s:' % field,

            if s[0].endswith('s'):
                print getattr(self, field)
            else:
                print '0x%x' % getattr(self, field)


class UnorderedEncodable(Encodable):
    @classmethod
    def fmt(cls, bits):
        return cls.types[bits].fmt(bits)

    @classmethod
    def decode(cls, data, bits):
        return cls.types[bits].decode(data, bits)

    def encode(self, bits):
        return self.types[bits].encode(self)


class Constant(object):
    @classmethod
    def lookup(cls, value):
        for name, val in inspect.getmembers(cls):
            if not name.startswith('__') and val == value:
                return name

        raise ValueError('no constant of type %s with value %s' %
                         (cls.__name__, value))


class DecodeError(RuntimeError):
    pass


class EncodeError(RuntimeError):
    pass


class ElfN_Ehdr(Encodable):
    fields = (
        (('16s', '16s'), 'e_ident'),
        ('HH',           'e_type'),
        ('HH',           'e_machine'),
        ('II',           'e_version'),
        ('IQ',           'e_entry'),
        ('IQ',           'e_phoff'),
        ('IQ',           'e_shoff'),
        ('II',           'e_flags'),
        ('HH',           'e_ehsize'),
        ('HH',           'e_phentsize'),
        ('HH',           'e_phnum'),
        ('HH',           'e_shentsize'),
        ('HH',           'e_shnum'),
        ('HH',           'e_shstrndx'),
    )

    EI_NIDENT = 16

    class EI_CLASS(Constant):
        ELFCLASSNONE = 0x0
        ELFCLASS32 = 0x1
        ELFCLASS64 = 0x2

    class EI_DATA(Constant):
        ELFDATANONE = 0x0
        ELFDATA2LSB = 0x1
        ELFDATA2MSB = 0x2

    class EI_VERSION(Constant):
        EV_NONE = 0x0
        EV_CURRENT = 0x1

    class EI_OSABI(Constant):
        ELFOSABI_NONE = 0x0
        ELFOSABI_LINUX = 0x3

    class Machine(Constant):
        EM_NONE = 0x0
        EM_M32 = 0x1
        EM_SPARC = 0x2
        EM_386 = 0x3
        EM_68K = 0x3
        EM_88K = 0x4
        EM_860 = 0x7
        EM_MIPS = 0x8
        EM_PARISC = 0xf
        EM_SPARC32PLUS = 0x12
        EM_PPC = 0x14
        EM_PPC64 = 0x15
        EM_S390 = 0x16
        EM_ARM = 0x28
        EM_SH = 0x2a
        EM_SPARCV9 = 0x2b
        EM_IA_64 = 0x32
        EM_X86_64 = 0x3e
        EM_VAX = 0x4b

    class Type(Constant):
        ET_NONE = 0x0
        ET_REL = 0x1
        ET_EXEC = 0x2
        ET_DYN = 0x3
        ET_CORE = 0x4

    class Shstrndx(Constant):
        SHN_UNDEF = 0x0
        SHN_LORESERVE = 0xff00
        SHN_LOPROC = 0xff00
        SHN_HIPROC = 0xff1f
        SHN_ABS = 0xfff1
        SHN_COMMON = 0xfff2
        SHN_HIRESERVE = 0xffff


class Elf32_Phdr(Encodable):
    fields = (
        ('I ', 'p_type'),
        ('I ', 'p_offset'),
        ('I ', 'p_vaddr'),
        ('I ', 'p_paddr'),
        ('I ', 'p_filesz'),
        ('I ', 'p_memsz'),
        ('I ', 'p_flags'),
        ('I ', 'p_align'),
    )


class Elf64_Phdr(Encodable):
    fields = (
        (' I', 'p_type'),
        (' I', 'p_flags'),
        (' Q', 'p_offset'),
        (' Q', 'p_vaddr'),
        (' Q', 'p_paddr'),
        (' Q', 'p_filesz'),
        (' Q', 'p_memsz'),
        (' Q', 'p_align'),
    )


class ElfN_Phdr(UnorderedEncodable):
    types = {32: Elf32_Phdr, 64: Elf64_Phdr}


class ElfN_Shdr(Encodable):
    fields = (
        ('II', 'sh_name'),
        ('II', 'sh_type'),
        ('IQ', 'sh_flags'),
        ('IQ', 'sh_addr'),
        ('IQ', 'sh_offset'),
        ('IQ', 'sh_size'),
        ('II', 'sh_link'),
        ('II', 'sh_info'),
        ('IQ', 'sh_addralign'),
        ('IQ', 'sh_entsize'),
    )


class Elf32_Sym(Encodable):
    fields = (
        ('I ', 'st_name'),
        ('I ', 'st_value'),
        ('I ', 'st_size'),
        ('B ', 'st_info'),
        ('B ', 'st_other'),
        ('H ', 'st_shndx'),
    )


class Elf64_Sym(Encodable):
    fields = (
        (' I', 'st_name'),
        (' B', 'st_info'),
        (' B', 'st_other'),
        (' H', 'st_shndx'),
        (' Q', 'st_value'),
        (' Q', 'st_size'),
    )


class ElfN_Sym(UnorderedEncodable):
    types = {32: Elf32_Sym, 64: Elf64_Sym}


class ElfN_Rel(Encodable):
    fields = (
        ('IQ', 'r_offset'),
        ('IQ', 'r_info'),
    )


class ElfN_Rela(Encodable):
    fields = (
        ('IQ', 'r_offset'),
        ('IQ', 'r_info'),
        ('IQ', 'r_addend'),
    )


class ElfN_Dyn(Encodable):
    fields = (
        ('IQ', 'd_tag'),
        ('IQ', 'd_val'),  # union {d_val, d_ptr} d_un
    )

    @property
    def d_ptr(self):
        return self.d_val

    @d_ptr.setter
    def d_ptr(self, value):
        self.d_val = value


def decode_bits(data):
    if len(data) < ElfN_Ehdr.EI_NIDENT:
        raise DecodeError('data too small for e_ident (<%d)' %
                          ElfN_Ehdr.EI_NIDENT)

    if data[:4] != '\x7fELF':
        raise DecodeError('invalid magic value')

    elif data[4] == ElfN_Ehdr.EI_CLASS.ELFCLASS32:
        bits = 32
    elif data[4] == ElfN_Ehdr.EI_CLASS.ELFCLASS64:
        bits = 64
    elif data[4] == ElfN_Ehdr.EI_CLASS.ELFCLASSNONE:
        raise DecodeError('only 32 and 64 bits are supported')
    else:
        raise DecodeError('invalid bits')

    needed = struct.calcsize(ElfN_Ehdr.fmt(bits))

    if len(data) < needed:
        raise DecodeError('data too small for ELF header (<%d)' % needed)

    return bits
