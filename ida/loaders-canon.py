#!/usr/bin/env python3 -u
""" Canon firmware loader """
from struct import unpack, error
from zlib import decompress
from io import BytesIO

import idc
import idaapi


class Container:
    """ Container type package """
    HDR_SIZE = 32
    MAGIC_SIZE = 4
    def __init__(self, stream):
        self._hsize   = Container.HDR_SIZE
        self._hdr     = None
        self._content = None
        self._stream  = stream

    def hdr_parse(self, fmt):
        """ parse header from stream """
        self._hdr = self._r(self._hsize)
        try:
            return unpack(fmt, self._hdr)
        except error:
            return None

    def _r(self, size):
        """ read from buffer """
        return self._stream.read(size)

    def handle(self):
        """ parse container """
        raise NotImplementedError()

    @property
    def hdr(self):
        """ header bytes """
        if self._hdr is None:
            self.handle()
        return self._hdr

    @property
    def content(self):
        """ content bytes """
        if self._content is None:
            self.handle()
        return self._content

    @property
    def stream(self):
        """ content bytes stream """
        return BytesIO(self.content)

class CEFW(Container):
    """ CEFW container type """
    magic = b'CEFW'

    def __init__(self, stream):
        super().__init__(stream)
        self._uncompressed_size  = None
        self._pkg_size           = None

    def handle(self):
        """ parse CEFW block """
        print('[*] handling CEFW block')
        obj = self.hdr_parse("<4sIIIIIII")
        if obj is None:
            raise ValueError()
        magic             = obj[0]
        hdr_size          = obj[1]
        uncompressed_size = obj[2]
        pkg_size          = obj[3]

        if magic != CEFW.magic:
            raise ValueError(f"unexpected CEFW magic {magic:4x}")
        if hdr_size != self._hsize:
            raise ValueError(f"unexpected CEFW header size {hdr_size:04x}")

        print(f'    pkg size: 0x{pkg_size:x} (0x{uncompressed_size:x})')
        print('    decompressing…', end='')
        data = decompress(self._r(pkg_size))
        if data is None or len(data) != uncompressed_size:
            raise ValueError("decompress error")
        print(' done')

        self._uncompressed_size = uncompressed_size
        self._content = data

class NCFW(Container):
    """ NCFW container type """
    magic = b'NCFW'

    def __init__(self, stream):
        super().__init__(stream)
        self._obfct = None
        self._sig   = None
        self._ncas  = []
        self._mms   = []

    def handle(self):
        """ parse NCFW block """
        print('[*] handling NCFW block')
        obj = self.hdr_parse("<4sIIIIIII")
        if obj is None:
            raise ValueError()
        magic        = obj[0]
        pkg_size     = obj[2]
        hdr_size     = obj[3]
        content_size = obj[4]

        if magic != NCFW.magic:
            raise ValueError(f"unexpected NCFW magic {magic:4x}")
        if hdr_size != self._hsize:
            raise ValueError(f"unexpected NCFW header size {hdr_size:04x}")

        signature_size = pkg_size - content_size - hdr_size
        print(f'    pkg size: 0x{pkg_size:x}')
        print('    deobfuscating…', end='')
        self._obfct   = self._r(content_size)
        self._content = bytes(i for i in self.deobfuscate())
        self._sig     = self._r(signature_size)
        print(' done')

    def deobfuscate(self):
        """ Canon deobfuscator """
        for idx, value in enumerate(self._obfct):
            value = (value - idx - 1) & 0xff
            value = (~((2 * value) | (value >> 7))) & 0xff
            yield value

    def add_mms(self, stream, size):
        """ search for Mms """
        if peek_magic(stream) == SIG.magic:
            try:
                SIG(stream).handle()
                while stream.tell() < size:
                    # pylint: disable=invalid-name
                    mm = MM(stream)
                    self._mms.append(mm.addr)
                return True
            except ValueError:
                print('[!] unexpected Mm, discarding…')
                self._mms.clear()
        return False

    def add_ncas(self):
        """ parse all NCAs """
        try:
            stream = self.stream
            nca = NCA(stream)
            if len(self._ncas) == 0:
                if not self.add_mms(nca.stream, len(nca.content)):
                    print('[!] Missing Sig & Mm header in first NCA')

            self._ncas.append(nca)
            if len(self._mms) > 0:
                for maddr in self._mms:
                    nca = NCA(stream)
                    naddr = nca.info['addr']
                    if maddr != naddr:
                        print(f'[!] unexpected NCA addr {naddr:4x} {maddr:4x}')
                    self._ncas.append(nca)

                if stream.tell() != len(self.content):
                    print('[!] unexpected trailing data in NCFW')
            else:
                while stream.tell() < len(self.content):
                    nca = NCA(stream)
                    self._ncas.append(nca)

        except ValueError:
            print('[!] unexpected NCA, discarding…')
            self._ncas.clear()

    @property
    def ncas(self):
        """ NCAs inside NCFW """
        return self._ncas

class NCA(Container):
    """ NCA block type """
    magic = b'\xaf\xaf\x9c\x9c'

    def __init__(self, stream):
        super().__init__(stream)
        self._hsize = Container.HDR_SIZE * 2
        self._addr  = None
        self._vaddr = None

    def handle(self):
        """ parse NCA block """
        print('[*] handling NCA  block')
        obj = self.hdr_parse(">4sIII4sHbbIIIIIIIIII")
        if len(self._hdr) != self._hsize:
            # EOF when unknown number of NCA
            return

        magic        = obj[0]
        addr         = obj[1]
        date         = obj[2]
        #flag         =_obj[3]
        #XXxx         =_obj[4]
        version      = obj[5]
        compressed   = obj[6]
        rom_kind     = obj[7]
        pkg_size     = obj[8]
        content_size = obj[9]
        vaddr        = obj[11]
        #cksum        = obj[17]

        if magic != NCA.magic:
            raise ValueError(f"unexpected NCA magic {magic:4x}")
        hdr_size = pkg_size - content_size
        if hdr_size != self._hsize:
            raise ValueError(f"unexpected NCA header size {hdr_size:04x}")

        print(f'    blk addr: 0x{addr:08x} size: 0x{pkg_size:x}')
        vers = f"{version:04x}"
        print(f'    version: {vers[:2]}.{vers[2:]} ({date:08x})')
        flags = str.join(',', filter(None, [
          "compressed" if compressed == 2 else None if compressed == 1 else "invalid comp",
          "code" if vaddr else None
        ]))
        kind = "language" if rom_kind == 2 else \
               "DCON" if rom_kind == 4 else f"{rom_kind:02x}"
        print(f'    kind: {kind} flags: {flags if flags else "none"}')

        self._content = self._r(content_size)
        self._addr = addr
        self._vaddr = vaddr

    def write(self, path='./'):
        """ write NCA to disk """
        print('    write package…', end='')
        # pylint: disable=invalid-name
        with open(f'{path}seg_0x{self._addr:x}.bin', 'wb') as f:
            f.write(self.hdr + self.content)
        print(' done')

    @property
    def info(self):
        """ NCA info for IDA segment """
        if self._content is None:
            self.handle()
        return {
          "addr":  self._addr,
          "vaddr": self._vaddr,
          "size":  len(self.hdr + self.content),
          "buf":   self.hdr + self.content,
        }

class SIG(Container):
    """ Sig block type """
    magic = b'\x18\x18\xe7\xe7'

    def __init__(self, stream):
        super().__init__(stream)
        self._sig = None

    def handle(self):
        """ Parse Sig block """
        print('[*]     handling Sig block')
        obj = self.hdr_parse(">4sIIIIIII")
        magic    = obj[0]
        hdr_size = obj[1]
        pkg_size = obj[2]

        if magic != SIG.magic:
            raise ValueError(f"unexpected Sig magic {magic}")
        if hdr_size != self._hsize:
            raise ValueError(f"unexpected Sig header size {hdr_size:04x}")

        self._sig = self._r(pkg_size)

    @property
    def sig(self):
        """ SIG signature """
        if self._sig is None:
            self.handle()
        return self._sig

class MM(Container):
    """ Mm block type """
    magic = b'\x96\x96\xc3\xc3'
    size  = Container.HDR_SIZE

    def __init__(self, stream):
        super().__init__(stream)
        self._addr = None

    def handle(self):
        """ Parse Mm block """
        print('[*]     handling Mm block')
        obj = self.hdr_parse(">4sIIIIIII")
        magic = obj[0]
        addr  = obj[2]

        if magic != MM.magic:
            raise ValueError(f"unexpected Mm magic {magic}")

        self._addr = addr

    @property
    def addr(self):
        """ MM addr """
        if self._addr is None:
            self.handle()
        return self._addr

def peek_magic(stream):
    """ retrieve block type """
    try:
        magic = unpack("<4s", stream.read(Container.MAGIC_SIZE))[0]
        stream.seek(-Container.MAGIC_SIZE, 1) # os.SEEK_SET)
        return magic
    except error:
        return None

# pylint: disable=invalid-name
def accept_file(f, _):
    """ return if the file looks like a CEFW/NCFW binary """
    f.seek(0)
    magic = peek_magic(f)
    if magic not in (CEFW.magic, NCFW.magic):
        return 0

    #return f'Canon {magic:4x} binary'
    return 'Canon firmware binary'

def load_file(f, _1, _2):
    """ load file in IDA """
    magic = peek_magic(f)
    if magic == CEFW.magic:
        block = CEFW(f)
        f = block.stream

        magic = peek_magic(f)
        if magic is None:
            print('[!] invalid CEFW block')
            return 0
    ncfws = []
    while magic == NCFW.magic:
        block = NCFW(f)
        block.add_ncas()
        ncfws.append(block)
        magic = peek_magic(f)

    segs = []
    for block in ncfws:
        for info in filter(lambda x: x['vaddr'] != 0,
                           (b.info for b in block.ncas)):
            segs.append(info)
        #XXX
        for b in block.ncas:
            if b.info['vaddr'] != 0:
                b.write('/tmp/')

    idaapi.set_processor_type('arm', idaapi.SETPROC_LOADER)

    for seg in segs:
        f_ea = seg['vaddr']
        if seg['size'] % 0x1000 != 0:
            sz = seg['size'] + (0x1000 - (seg['size'] % 0x1000))
            t_ea = f_ea + sz
        else:
            t_ea = f_ea + seg['size']
        if idaapi.add_segm(0, f_ea, t_ea, "FIRMWARE", "CODE") != 1:
            print('[!] idaapi.add_segm error')
        idaapi.put_bytes(f_ea, seg['buf'])

    return 1
