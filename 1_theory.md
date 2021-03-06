# return to fixup (fake link_map)

return_to_fixup - способ эксплуатации, похожий на return_to_libc или
return_to_plt.  Данная техника может использоваться для обхода ASLR, но что
интереснее, она позволяет вычислить адрес функции из динамической библиотеки по
ее имени (0-термиринованная с строка). При этом не требуется информация о
структуре libc, как в случае с return_to_libc.

Необходимые условия для применения: 
* memory leak указателя из GOT таблицы (GOT[1], возможно GOT[2] в зависимости
от способа получения code execution)
* memory write в известный адрес памяти (около 500 байт)
* контроль eip (роп цепочка \ адрес возврата \ перезапись элемента GOT)

Работает техника как на x86, так и на x64.

#### зачем это нужно, если есть return to libc

Для обхода (игнорирования) ASLR без информации о libc.
Стандартный способ обойти ASLR - получить адрес загрузки libc и относительно
него вычислить адрес интересующей нас функции / гаджета.  Например, мы хотим
вызвать system, зная адрес puts (va_puts - absolute virtual address). Тогда
нужно вычислить адрес загрузки libc:
    va_libc = va_puts - rva_puts
где rva_puts - смещение puts внутри libc, для нахождения которого нужна
информация о версии libc.

return_to_fixup позволяет вычислить адрес функции без доступа к информации о
libc.

### Краткое описание техники:

При использовании динамической загрузки функций адрес функции из библиотеки не
известен к моменту первого вызова функции.  Во время первого обращения к
функции вызывается dl_fixup из libc.so, которая вычисляет адрес, по которому
загружена функция.  Для вычисления адреса функции используется 2 значения:
индекс функции (значение, заранее определенное для каждой функции в got.plt
секции и структура link_map из global offset table).  Причем структура link_map
при вызове trampoline_fixup одинаковая для всех функций.  То есть, динамический
лоадер различает вызываемые функции ТОЛЬКО по индексу.  Идея техники в том, что
можно вызвать trampoline_fixup с контролируемыми аргументами так (построить
link_map и выбрать reloc_arg), чтобы он нашел и вызвал произвольную функцию по
ее имени (Условно find_function("system"), чтобы потом сделать
system("/bin/sh")).

### Обозначения

Как работает GOT и plt описано здесь: [GOT and plt](got_plt.md)

Список обозначений, используемых в дальнейшем:
* GOT - global offset table
* GOT[FUNC] - запись в GOT, в которой хранится адрес func
    GOT[0..2] зарезервированы системой
    GOT[2] хранит адрес trampoline_fixup
* plt - таблица plt-заглушек
* <func>@plt - plt-заглушка функции <func> 
    например, gets@plt для функции gets
* plt[0] - общая часть всех plt-заглушек, условно можно считать первой функцией
    в таблице plt-заглушек (располагается первой в памяти)

Дальнейшие обозначения будут объяснены по ходу и приводятся, чтобы все
обозначения были собраны в одном месте:
* wrapper_fixup(reloc_arg)
Как известно, при вызове функций из динамической библиотеки они вызываются
через @plt трамплин. Рассмотрим внимательнее последовательность вызовов и
договоримся насчет обозначений, используемых в дальнейшем.  Ассемблерный код с
небольшими правками для удобства (листинг 1.1)
```asm
<func@plt+0>:     jmp    DWORD PTR GOT[FUNC]
<func@plt+6>:     push   reloc_arg        ; unique for every func
<func@plt+11>:    jmp    plt[0]
...
<plt[0]>:         push   DWORD PTR GOT[1] ; link_map
<plt[0] + 6>:     jmp    DWORD PTR GOT[2] ; trampoline_fixup
```
Назовем wrapper_fixup(reloc_arg) последовательность инструкций, начинающуюся с
func@plt+6.  Она сохраняет reloc_arg на стек, дальше следуют прыжок plt[0] и
вызов trampoline_fixup(link_map, reloc_arg). 

* trampoline_fixup(link_map, reloc_arg) - вызывается в wrapper_fixup
    трамплин к функции dl_fixup, его устройство будет описано ниже
* link_map - управляющая структура, так же описанная ниже
* link_map.getName(reloc_arg) - описание после кода dl_fixup

### Теоретические основы

В данной части будет описана работа и внутреннее устройство динамического
лоадера функций. Так мы сформулируем и уточним цель: что именно мы хотим
сделать.  После того, как цель будет ясна, мы опишем детали техники, то есть
как мы достигнем цели, в части 2.  Мы рассмотрим общую схему работы лоадера и
некоторые детали, существенные для техники, с помощью пристального взляда в
исходники.

Общая цель: вызвать wrapper_fixup так, чтобы он (то есть внутренняя функция
dl_fixup) вернул нужную нам функцию.  (грубый пример: вместо puts("/bin/sh")
вызывать system("/bin/sh")

### Внутреннее устройство wrapper_fixup

В этом разделе рассматривается вызов последовательность вызовов dl_resolve,
dl_runtime_resolve, dl_fixup.  
Ранее мы договорились называть wrapper_fixup код, который вызывается при
первом обращении к функции. Он сохраняет аргументы для функции, ищет адрес
функции и вызывает ее с сохраненными аргументами.
Если рассмотреть подробнее, происходит следующая последовательность вызовов:
```code
| wrapper_fixup
| 
|     push reloc_arg
|     push link_map
| 
|     //jmp trampoline_fixup 
|---> dl_runtime_resolve_avx_opt 
    |     принимает аргументы через стэк: got[1], index
    | 
    |---> dl_runtime_resolve_sse_vex
        | 
        |---> dl_fixup(struct link_map* l, long reloc_arg) 
            |     dl_lookup_symbol_x(char* symbol_name, ...)
            |     ...
            | 
            |     replace pointer in plt section
            |     return function pointer
             
          call function pointer
```
(фиг.1: последовательность вызовов в wrapper_fixup)

Последовательность вызовов, подготавливающую вызов dl_fixup мы договорились
называть trampoline_fixup.  GOT[2] содержит адрес функции
dl_runtime_resolve_avx_opt. Функции dl_runtime_resolve_avx_opt и
dl_runtime_resolve_sse_vex являются трамплином для dl_fixup - именно эту
последовательность мы и называем trampoline_fixup. 

Главная интересующая нас функция - dl_fixup, она принимает указатель на
системную структуру link_map и индекс функции.  Предыдущие функции и
ассемблерный код являются трамплином, который подготавливает для нее аргументы.
dl_runtime_resolve_sse_vex так же сохраняет параметры для целевой функции и
вызывает ее после того, как dl_fixup ее найдет.

Все функции, вызываемые в wrapper_fixup, являются частью динамического лоадера
ld.so. Код, необходимый для понимания техники, приводится ниже. 

Теперь мы знаем, что за загрузку функции отвечает dl_fixup, и она принимает
лишь 2 аргумента. Предыдущие функции выполняют вспомогательные действия.
Уточним нашу цель: вызывать dl_fixup с контролируемыми аргументами так, чтобы
она вернула нужную нам функцию.

### Путь внутри dl_fixup 

dl_fixup использует структуру link_map для получения имени функции
(null-terminated string). Эта структура достаточно сложная, она хранит
информацию о строении elf-файла и об адресном пространстве процесса. 

Для организации доступа к именам функций в таблице строк используется система
из указателей.  Эта система показана на схеме link_map (фиг. 1.1):
![схема link_map](refs/link_map.png)

Рекомендуется изучать схему и код функции параллельно.
Пояснение к фигуре в комментариях к коду dl_fixup и после.

Разберемся с тем, как именно работает dl_fixup, и куда мы хотим попасть внутри.
Код функции приведен к более удобному виду: макросы заменены на итоговые
значения. Мы считаем, что работаем с x32, например ElfW_Addr заменяется на
Elf32_Addr (аналогично для x64).  Определения структур сокращены до
интересующих нас полей. Файл с [определениями](refs/header_fixup.h) (влож. 1.1).
Сокращенные участки кода обозначены /*... ...*/. (листинг 1.1).
```c
Elf32_Addr _dl_fixup (struct link_map *l, Elf32_Word reloc_arg)
{
    // в symtab (symbol table) сохраняется указатель на первый элемент таблицы символов
    const Elf32_Sym *const symtab
    = (const void *) l->l_info[DT_SYMTAB]->d_un.d_ptr;
    // в strtab (string table) сохраняется указатель на начало таблицы строк
    const char *strtab = (const void *) l->l_info[DT_STRTAB]->d_un.d_ptr;

    // в reloc (relocation) сохраняется указатель на элемент таблицы релоков,
    // отвечающий искомой функции: берется смещение reloc_arg от начала таблицы
    // релоков, как мы помним - это аргумент, который кладет на стек
    // инициализирующий код в plt части функции
    const Elf32_Rela *const reloc
    = (const void *) (l->l_info[DT_JMPREL]->d_un.d_ptr + reloc_arg);

    // вычисляем символ, отвечающий искомой функции
    const Elf32_Sym *sym = &symtab[(reloc->r_info) >> 8];

    // определение переменных
    struct link_map *result;
    Elf32_Addr value;

    /* Sanity check that we're really looking at a PLT relocation.  */
    assert (ELF32_R_TYPE(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

    /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
    //#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)
    if (ELF32_ST_VISIBILITY(sym->st_other) == 0) {
        /* DESIRED PATH */
        // проверка версии - в нашем случае мы будем передавать сюда NULL
        const struct r_found_version *version = NULL;
        if (l->l_info[DT_NUM + DT_THISPROCNUM + DT_VERNEEDNUM - (DT_VERSYM)] != NULL) {
            /*... undesired path, specified version of function is required ...*/
        }

        /*... get some global flags ...*/
        int flags = DL_LOOKUP_ADD_DEPENDENCY;

        /* THIS IS OUR TARGET */
        // вызов поиска по символу: первый параметр - c-строка, имя искомой функции
        result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                      version, ELF_RTYPE_CLASS_PLT, flags, NULL);

        /*... function address saved, now post actions ...*/
        // вычисление адреса функции по значению, найденному ранее
        value = sym ? ((result ? result->l_addr : 0) + sym->st_value) : 0;
    } else {
        /*... undesired path ...*/
        /* We already found the symbol.  The module (and therefore its load
        address) is also known.  */
    }

    /*... relocation if needed ...*/

    /* Finally, fix up the plt itself.  */
    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
    return *rel_addr = value;
}
```
[Функция без сокращений](refs/add_fixup_full.c) (влож. 1.2)

Как видно из кода и пояснений, dl_fixup использует экземпляр структуры link_map
для получения имени функции. Договоримся обозначать 
link_map.getName(RA) == NAME, если вызов dl_fixup(lm, ra) получает имя NAME.

Пояснение к схеме link_map. На схеме мы видим обозначения самой структуры
link_map, а так же 4-х таблиц: таблица строк (желтая), таблица символов
(зеленая), таблица релокаций (филолетовая), и набор динамических записей
(синий).  Набор а не таблица, так как элементы не обязательно образуют
непрерывный в памяти последовательный массив.  В поле l_info требуется хранить
указатели на структуры разных типов. Для этого применяется показанная на фигуре
схема: хранится указатель на динамическую сущность, в которой хранится тип
целевой структуры и указатель на нее (что-то вроде реализации виртуальных
указателей).

Примечание по использованию reloc_arg: в зависимости от архитектуры может
использоваться как индекс или как смещение.
x32:
reloc_arg == reloc_offset (то есть reloc_index = reloc_arg / sizeof(PLTREL))
x64:
reloc_arg == reloc_index (то есть reloc_offset = reloc_arg * sizeof(PLTREL))

Примечание2: таблица строк это просто массив байт, в котором строкой является
любая последовательность, оканчивающаяся \x00.

Дополним цель: пройти по правильному пути до вызова dl_lookup_symbol_x.

Полная версия исходного кода:
dl_fixup:           glibc/elf/dl-runtime.h. 
struct link_map:    glibc/include/link.h. 

### параметры dl_lookup_symbol_x

Обратим внимание на вызов функции dl_lookup_symbol_x в листинге 1.2:1
```c
result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
              version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```
Определение этой функции (файл glibc/elf/dl-lookup.h):
```c
typedef struct link_map *lookup_t;
/* Search loaded objects' symbol tables for a definition of the symbol
   UNDEF_NAME, perhaps with a requested version for the symbol.     */
lookup_t
_dl_lookup_symbol_x (const char *undef_name, struct link_map *undef_map,
		     const Elf32_Sym **ref,
		     struct r_scope_elem *symbol_scope[],
		     const struct r_found_version *version,
		     int type_class, int flags, struct link_map *skip_map)
```
Первый параметр undef_name самый **важный** для нас - это имя функции, полученное
ранее, согласно схеме на фиг. 1.1. undev_name = strtab + sym->st_name, то есть
адрес таблицы строк + смещение в таблице строк.
Еще один **важный** параметр - symbol_scope. Это указатель лист из link_map'ов,
описывающих адресное пространство.  Как мы видим, в качестве этого параметра
передается l->l_scope. Это указатель на массив r_scope_elem структур, которые
содержат указатели на link_map'ы, каждый из которых описывает свою часть
адресного пространства: по одному для разделяемой библиотеки. Без корректно
заполненной структуры dl_lookup не сможет найти адрес функции и произойдет
ошибка (Symbol not found).

В стандартной структуре link_map поле l_scope указывает на соседнее (через
одно) поле l_scope_mem. То есть l->l_scope = &(l->l_scope_mem), равно адрес
link_map + смещение поля l_scope_mem.  Это постоянная величина. Мы используем
эту информацию при создании собственной link_map - fake_link_map.

Остальные параметры:
undef_map - указатель на link_map, переданный в dl_fixup
ref - адрес символа функции (из таблицы symtab)
version - опционально, версия символа, мы будем передавать NULL
type, flags, skip_map - неконтролируемые захардкоженные параметры.

Уточним цель: чтобы получить адрес функции с именем "hacker_function", нужно
вызвать dl_fixup с контолируемыми аргументами (struct link_map * , int) так,
чтобы дойти до dl_lookup_symbol_x и ее первым аргументом была строка
"hacker_function".

### POC: создаем link_map - ломаем сами себя

Мы изучили dl_fixup и используемые структуры. default_link_map - структура,
адрес которой хранится в GOT[1] нормальной программы. Теперь мы хотим построить
свою fake_link_map.

Опишем требования (треб. 1.0) к функции построения и результату:
При создании:
* выбираем сами пары (name, reloc_arg) - имя функции и отвечающий ей reloc_arg.
* используем адрес default_link_map (ТОЛЬКО адрес, значения полей не используются)
При использовани:
* для любого reloc_arg из пар (п.1) 
    fake_link_map.getName(reloc_arg) == name;
    dl_fixup(fake_link_map, reloc_arg) проходит до вызова dl_lookup_symbol_x по
    нужному пути (см. листинг 1.1)

Пример первый: [POC c source](examples/poc1_fixup.c).
При запуске требуется указать адрес GOT и reloc_arg функции strchr@plt собранного бинаря, 
поэтому удобнее запустить с помощью лаунчера [POC2 python launcher](examples/launch_poc1.py)
Программа ломает сама себя и используется лишь для демонстрации правдивости
гипотезы.
Функция fill_link_map_fake создает fake_link_map, придерживаясь требований.
Выбрана только одна пара ("system", reloc_arg_1), так как этого достаточно для
демонстрации.  Данный POC показывает, что dl_fixup использует только несколько
полей из struct link_map.  При этом можно пройти по желаемому пути, функция
dl_lookup_symbol_x корректно сработает, и мы найдем функцию с нужным нам
именем.

dl_lookup_symbol_x использует 4-й параметр symbol_scope для получения
информации об адресном пространстве и загруженных библиотеках.  dl_fixup в
качестве symbol_scope передает l->l_scope (см. комментарий в предыдущем
пункте).  Поэтому мы запишем в fake_link_map указатель на
default_link_map->l_scope_mem.

* замечание: изучение исходного кода необходимо, но может быть не достаточно.
При создании POC эксплоита я рекомендую так же пройтись в дебагере по dl_fixup
и используемым структурам и сопоставить ассемблерный код с c исходниками. Это
позволит убедиться в правильности нашего понимания работы функции, проверить
индексы в массивах и тд. Для удобства работы в отладчике удобно скомпилировать
glibc с символами отдельно и линковать примеры с ней (если коненчо компиляция
glibc может быть удобной).

### POC2: создание fake_link_map с помощью python

Теперь когда мы убедились, что техника работает, давайте напишем функцию
создания fake_link_map'ов, удовлетворяющую треб. 1.0 на питоне.  Это
по-прежнему POC, ломающий сам себя, только на этот раз программа считывает
fake_link_map из stdin. Запускать POC2 и cоздавать fake_link_map мы будем с
помощью скрипта.

[POC2 c source](examples/poc2_fixup.c)

[POC2 python launcher](examples/launch_poc2.py)

Рассмотрим функцию создания link_map - main в [generate32.py](examples/generate32.py):
fake_link_map = main(...)
Петвые 2 параметра определяются в runtime и определяют границы применимости
техники:
* new_addr: адрес, куда будет сохранена fake_link_map 
    (memory-write по известному адресу)
* old_addr: адрес, где находится стандартный link_map (memory-leak GOT[1])

Остальные параметры могут выбираться из соображений удобства:
* write_addr
* strtab
* srindex

create_link_map32 возвращает строку как содержимое памяти. Размер fake_link_map
меньше sizeof(link_map), так как в dl_fixup не используются все поля, и
fake_link_map может иметь любой размер, но содержать последнее используемое
поле с максимальным смещением. Помимо самой структуры link_map, требуется
создать структуру ссылок, удовлетворяющую схеме на фиг. 1.1.  Для уменьшения
размера payload create_link_map вписывает вспомогательные структуры в
промежутки между используемыми полями fake_link_map. 
Схема размещения ссылок внутри link_map показана на фиг. 1.2.
![фиг. 1.2](refs/fake_link_map.png)

### Итоги

Мы изучили схему работы dl_fixup и нашли способ построить fake_link_map так,
чтобы dl_fixup работала корректно и находила нужные нам функции.

Еще раз об ограничениях: требуется 
* контроль eip
* узнать адрес существующей default_link_map: memory-leak
    (хранится в GOT[1], но вообще, может быть получен со стека)
* знать адрес, куда мы сохраним fake_link_map: memory-write

memory-leak адреса default_link_map требуется, чтобы прибавить к нему смещение
и получить &default_link_map.l_scope_mem - корректный массив r_scope_elem *,
который позволит dl_lookup найти нужную функцию.

memory-write **по извстному адресу** нужен, чтобы построить систему ссылок
между тремя таблицами, используемыми в dl_fixup для получения имени функции.

Минимальный размер в байтах fake_link_map (размер payload) определяется
оффсетом последнего используемого поля - link_map.l_scope:

    min_size = offset(l_scope) + sizeof(void*)

Для х32 этот оффсет равен 0x1cc и минимальный размер 0x1cd, для x64 - 0x380 и
0x388 соответственно. В общем случае, как показано в следующей части,
fake_link_map можно строить так, чтобы она содержала несколько имен функций для
нескольких reloc_arg, не превышая минимальный размер. Потенциально, превысив
минимальный необходимый размер, можно построить fake_link_map, содержащую
произвольное число имен.

#### сравнение с return_to_libc

Для return_to_libc так же требуется memory-leak и контроль eip, но
return_to_fixup позволяет писать более надежные эксплоиты, не зависящие от
версии libc.

В return_to_libc информация о libc, то есть внутренние отступы функций,
требуется для получения базового адреса libc и последующего вычисления
абсолютного адреса интересующий нас функции. В return_to_fixup мы не
использовали ни значение базового адреса libc, ни значения оффсетов функций.

В [части 2](2_practice.md) рассмотрен еще один пример применения return_to_fixup на
более интересном файле и подробное сравнение с return_to_libc.

#### возможные стратегии использования:

Вызов:
* вызов через перезапись GOT[FUNC] + jump to func@plt
* вызов через jump to plt[0]
* memory-leakk GOT[2] + jump to GOT[2]

Использование:
* вызвать нужную функцию
* найти адреса нескольких функций и по ним найти версию libc + libc_base_addr

