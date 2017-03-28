Elf32_Addr _dl_fixup (struct link_map *l, Elf32_Word reloc_arg)
{
    const Elf32_Sym *const symtab
    = (const void *) l->l_info[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const void *) l->l_info[DT_STRTAB]->d_un.d_ptr;


    const Elf32_Rela *const reloc
    = (const void *) (l->l_info[DT_JMPREL]->d_un.d_ptr + reloc_arg);

    const Elf32_Sym *sym = &symtab[(reloc->r_info) >> 8];

    struct link_map *result;
    Elf32_Addr value;

    /* Sanity check that we're really looking at a PLT relocation.  */
    assert (ELF32_R_TYPE(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

    /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
    //#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)
    if (ELF32_ST_VISIBILITY(sym->st_other) == 0) {
        const struct r_found_version *version = NULL;
        //#define VERSYMIDX(sym)	(DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX (sym))
        if (l->l_info[DT_NUM + DT_THISPROCNUM + DT_VERNEEDNUM -  (DT_VERSYM)] != NULL) {
            // specified version of function is required
            const ElfW(Half) *vernum =
              (const void *) l->l_info[VERSYMIDX (DT_VERSYM)]->d_un.d_pt;
            ElfW(Half) ndx = vernum[ELF32_R_SYM(reloc->r_info)] & 0x7fff;
            version = &l->l_versions[ndx];
            if (version->hash == 0)
                version = NULL;
        }

        /* We need to keep the scope around so do some locking.  This is
        not necessary for objects which cannot be unloaded or when
        we are not using any threads (yet).  */
        int flags = DL_LOOKUP_ADD_DEPENDENCY;
        if (!RTLD_SINGLE_THREAD_P)
        {
            THREAD_GSCOPE_SET_FLAG ();
            flags |= DL_LOOKUP_GSCOPE_LOCK;
        }

#ifdef RTLD_ENABLE_FOREIGN_CALL
        RTLD_ENABLE_FOREIGN_CALL;
#endif

        result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                      version, ELF_RTYPE_CLASS_PLT, flags, NULL);

        /* We are done with the global scope.  */
        if (!RTLD_SINGLE_THREAD_P)
        THREAD_GSCOPE_RESET_FLAG ();

#ifdef RTLD_FINALIZE_FOREIGN_CALL
        RTLD_FINALIZE_FOREIGN_CALL;
#endif

        /* Currently result contains the base load address (or link map)
        of the object that defines sym.  Now add in the symbol
        offset.  */
        value = DL_FIXUP_MAKE_VALUE (result,
                   sym ? (LOOKUP_VALUE_ADDRESS (result)
                      + sym->st_value) : 0);
    } else {
        /* We already found the symbol.  The module (and therefore its load
        address) is also known.  */
        value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
        result = l;
    }

    /* And now perhaps the relocation addend.  */
    value = value + reloc->r_addend;

    if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

    /* Finally, fix up the plt itself.  */
    if (__builtin_expect (GLRO(dl_bind_not), 0))
    return value;

    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
    return *rel_addr = value;
}
