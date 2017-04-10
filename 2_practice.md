# Пример использования return_to_fixup: решение brainfuck

В данной части мы применим технику return_to_fixup для решения задания
brainfuck с сайта pwnable.kr. 
Что такое return_to_fixup написано [здесь](1_theory.md)
В тексте используются те же обозначения, что и в теоретическом описании.

Данное задание можно решить и без использования техники. Использование техники
позволяет получить более универсальное решение с меньшим числом ограничений:
для стандартного решения к заданию прилагается бинарный файл libc, используемый
для определения смещений функций. При использовании return_to_fixup
информация о libc не требуется.

Замечание: На сайте просили не писать writeup'ы для заданий, но пример с данным
заданием получается очень наглядным. Надеюсь никто не обидится на спойлер
решения.

### 1 общее описание и идея

Чтобы понять, как применяется техника, разберемся в задании и определим общую
идею решения.  brainfuck (или bf) - интерпретатор языка [brainfuck](https://ru.wikipedia.org/wiki/Brainfuck), в котором
реализованы операции:
```python
r = '>'     # move caret to right
l = '<'     # move caret to left
inc = '+'   # increment
dec = '-'   # decrement
p = '.'     # putchar - read symbol
g = ','     # getchar - write symbol
```
Пользователь вводит последовательность команд для интерпретатора (в дальшейшем
payload).  Список команд сохраняется в буфере на стеке длиной 1024 символа.
Tape - глобальный массив, над ним производятся преобразования с помощью команд.
Текущее положение в массиве хранится в глобальной переменной p.  Это очень
похоже на машину Тьюринга. 

Код (декомпилированный) интересующих нас функций из bf приведен ниже (листинг
2.1):
```c
int main(int argc, const char **argv, const char **envp)
{
	// common stuff
    size_t i; // [sp+28h] [bp-40Ch]@1
    char command_buf[1024]; // [sp+2Ch] [bp-408h]@1
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 1, 0);
    // initialize global variables
	// tape is declared in .bss section, so it will be 0's
    p = (int)&tape;
    puts("welcome to brainfuck testing system!!");
    puts("type some brainfuck instructions except [ ]");
	// prepare buffer and read user input
	// interesting pair of functions: command_buf in both functions as first argument
    memset(command_buf, 0, 0x400u);
    fgets(command_buf, 1024, stdin);
    for ( i = 0; i < strlen(command_buf); ++i ){
        // perform operation from user input
        do_brainfuck(command_buf[i]);
    }
    return 0;
}
// operation realization
int do_brainfuck(char command)
{
    int result; 
    result = command;
    switch (command)
    {
    case '>':
        result = p++ + 1; // increment p
        break;
    case '<':
        result = p-- - 1; // decrement p
        break;
    case '+':
        result = p;
        ++*p;             // increment value of *p
        break;
    case '-':
        result = p;
        --*p;             // decrement value of *p
        break;
    case '.':
        result = (char *)putchar(*p); // print value *p
        break;
    case ',':
        result = (char *)getchar();   // save value from stdin to *p
        *p = (_BYTE)result;
        break;
    case '[':
        result = (char *)puts("[ and ] not supported.");
        break;
    default:
        return result;
    }
    return result;
}
```
Как видно из листинга 1.1, чтение payload'a и цикл с выполнением введенных
команд находятся в функции main, каждая команда обрабатывается в do_brainfuck.

Расположение глобальных переменных в памяти (листинг 2.2)
```asm
.got.plt:
0x0804A000 _got_plt        segment dword public 'DATA' use32
0x0804A000                 assume cs:_got_plt
0x0804A000                 ;org 804A000h
0x0804A000 _GLOBAL_OFFSET_TABLE_ db 
; first 3 cells are reserved for system pointers
; GOT[0]
; GOT[1] = &link_map
; GOT[2] = trampoline_fixup
0x0804A00C off_804A00C     dd offset getchar          ; GETCHAR = 0 + 3 = 3
0x0804A010 off_804A010     dd offset fgets            ; FGETS = 1 + 3 = 4
0x0804A014 off_804A014     dd offset __stack_chk_fail ; 
0x0804A018 off_804A018     dd offset puts             ;
0x0804A01C off_804A01C     dd offset __gmon_start__   ;
0x0804A020 off_804A020     dd offset strlen           ;
0x0804A024 off_804A024     dd offset __libc_start_main;
0x0804A028 off_804A028     dd offset setvbuf          ;
0x0804A02C off_804A02C     dd offset memset           ; MEMSET = 8 + 3 = 11
0x0804A030 off_804A030     dd offset putchar          ; PUTCHAR = 9 + 3 = 12
0x0804A030 _got_plt        ends
; ...
.bss:
0x0804A080 ; char *p
; ...
0x0804A0A0 ; char tape[1024]
```

Уязвимость заключается в том, что интерпретатор не проверяет выход за пределы
tape и позволяет считывать и записывать байты не только внутри, но и за
пределами tape. При этом можно переместить указатель на произвольное место в
таблице GOT, считать или записать произвольные записи из этой таблицы. 

В частности, мы можем:

* переписать значение GOT[PUTCHAR] на адрес &main+143 (конкретное значение 143
объяснено позже)
Тогда, при обработке команды интерпретатора '.' мы вызовем putchar@plt
внутри do_brainfuck и вернемся в main к вызову memset (мы же помним, как
работает GOT), где сможем еще раз считать новый payload вместо того, чтобы
продолжить цикл.

* в файле есть последовательный вызов 
```c
memset(char *buf, ...);
fgets(char *buf, ...);
```
то есть две функции, которые вызываются с одинаковым первым аргументом -
указателем на буфер. Наша цель - модифицировать таблицу GOT так, чтобы вместо
этого вызвать 
```c
gets(char *buf);
system(char *buf);
```
и считать в gets строку "/bin/sh". (тогда мы вызовем system("/bin/sh")!)

Для иллюстрации сравним таблицы GOT нормальной программы и программы после
махинаций

GOT нормальной программы:
```asm
index | address   --> points to (description)
...
4     | 0x804a010 --> (<fgets>)
...
11    | 0x804a02c --> (<memset>)
```
GOT после махинаций:
```asm
index | address   --> points to (description)
...
4     | 0x804a010 --> (<system>)
...
11    | 0x804a02c --> (<gets>)
```
Главное ограничение - включенный ASLR, из-за которого мы не знаем адрес, по
которому загружена libc и, соответственно, gets и sytem.
Ключевая разница между стандартным способом и return_to_fixup - способ обхода
ASLR, то есть вычисление адресов функций в libc.

Теперь приведем более подробное описание для стандартного и нового способа
эксплуатаци.

### 2 стандартный способ

Наша конечная цель - записать в
GOT[MEMSET] и GOT[FGETS] адреса gets и system соответственно. Но как найти
абсолютный адрес функции gets и system?

#### обход ASLR - теория

При включенном ASLR адрес libc в адресном пространстве процесса изменяется при
каждом запуске.  Соответственно, изменяются и абсолютные адреса функций из
libc. Адреса удовлетворяют следующему соотношению:

    абс_адрес_функции_из_libc = адрес_загрузки_libc + смещение_внутри_libc

Чтобы найти адрес загрузки libc, нужна информация о функции, абсолютный адрес
которой известен.

    адрес_загрузки_libc = абс_адрес_изв_функции - смещение_изв_функции_в_libc

абс_адрес_изв_функции находится с помощью memory-leak.

#### Шаги для эксплуатации

Рассмотрим пример нахождения адреса gets: в таблице GOT есть запись, отвечающая
функции setvbuf - GOT[SETVBUF]. Мы прочитаем эту запись GOT, найдем смещение
функции setvbuf в файле libc.so и найдем адрес загрузки libc. Затем прибавим к
адресу загрузки смещение rva_gets (так же из файла libc.so) и получим
абсолютный адрес gets: va_gets.

    va - virtual address, rva - relative virtual address (offset inside libc)
    va_libc = va_setvbuf - rva_setvbuf
    va_gets = va_libc + rva_gets

аналогично, 

    va_system = va_libc + rva_system

Теперь непосредственно к эксплуатации (один из способов, идея общая, но
конкретная последовательность действий может отличаться):
Для эксплуатации потребуется 2 раза считать последовательность команд для
интерпретатора (payload1 и payload2).
В payload1 мы напечатаем GOT[SETVBUF] для расчета va_libc, и переписывающие
GOT[PUTCHAR] на адрес вызова memset в функции main, а затем вызовем putchar,
прыгнув на main, чтобы можно было считать вторую последовательность. Подробнее
про перезапись putchar будет написано ниже.

В payload2 мы перепишем GOT[MEMSET] и GOT[FGETS] на va_gets и va_system
соответственно. Снова вызовем putchar.  Оказавшись в main в третий раз, введем
"/bin/sh" и получим шелл.

И так, ключевые зависимости данного способа эксплуатации:

* возможность прочитать значение из GOT
* контроль eip (в данном случае - с помощью перезапись GOT[PUTCHAR])
* доступ к файлу libc для определения смещения функций

### 3 новый способ - концепт

Детали работы dl_fixup и структуры link_map, а так же обозначения
рассматриваются в [части 1](1_theory.md)

Примечание:
reloc_arg для x64 - индекс в таблице релокаций;
reloc_arg для x32 - не просто индекс, а готовое смещение в jmprel, то есть
index * sizeof(Elf32_Rela)

Пусть у нас нет доступа к файлу libc, и мы не можем определить внутренние
оффсеты функций.  Рассмотрим, как можно применить return_to_fixup для
вычисления адресов функций без знания оффсетов.  Как и в предыдущем способе,
наша цель - переписать GOT[MEMSET] и GOT[FGETS] на gets и system
соответственно.  
Для получения адресов gets и system специальным образом построим структуру
link_map - fake_link_map и вызовем dl_fixup(fake_link_map, reloc_arg) для двух
reloc_arg'ов - 0x10 и 0x8 (0x10 и 0x8 выбираются по желанию, можно использовать
другие значения).  Структуру fake_link_map построим так, чтобы (см.
обозначения):
    
    fake_link_map.getName(0x10) == 'gets'
    fake_link_map.getName(0x8) == 'system'

В части 1 уже был приведен пример построения фальшивой структуры fake_link_map.
Теперь мы воспользуемся тем же методом, но немного усовершенствуем его: мы
будем хранить в одной структуре две строки сразу (при этом, размер
fake_link_map не изменится, и там еще останется место для хранения большего
числа строк). Дополненная схема организации fake_link_map (фиг. 2.1):
![fake_link_map_double](refs/fake_link_map_double.png)

Таблицу GOT, модифицируем следующим образом:
модифицировать GOT:

    GOT[1] = &fake_link_map
    GOT[MEMSET] = &wrapper_fixup(0x10)
    GOT[FGETS] = &wrapper_fixup(0x8)

GOT[MEMSET] и GOT[FGETS] содержит адреса трамплинов, использующие в качестве
reloc_arg 0x8 и 0x10 соответственно.  Тогда при выполнении последовательности
memset, fgets на самом деле произойдет следующее:

    memset(buf, ...) -> memset@plt -> wrapper_fixup(0x8, fake_link_map) -> gets(buf);
    fgets(buf, ...) -> fgets@plt -> wrapper_fixup(0xc, fake_link_map) -> system(buf);

И мы сможем считать с помощью gets строку '/bin/sh', а затем сделать
system('/bin/sh')

### 4 новый способ - пошаговое описание

Количество шагов (возвратов для считывания и исполнения payload) будет больше,
чем в стандартном способе (ранее нам понадобилось 2 раза считать payload).

[demo_bf](examples/demo_bf.py) - return_to_fixup (советую открыть в отдельном окне).
Функция create_link_map32_2 является дополненной версией create_link_map32 из
предыдущей части: она создает link_map, содержащий 2 имени.

Эксплоит достаточно хорошо комментирован, поэтому ниже приведены только общие
пояснения.

class Actions: enum, перечисляющий возможные команды интерпретатора.

def interleave: вспомогательная функция, действие показано в docstring

class Generate: ООП-интерфейс для генерации стандартных последовательностей
действий, используемых в эксплоите, и отслеживающий текущее состояние
интерпретатора (прочитать \ записать 4 байта, переместить каретку на адрес)

Основное действие происходит в if __name__ == "__main__": блоке.

В части bf_file_constants указаны константы, полученные из самого файла bf.

Перепишем GOT[PUTCHAR] на va_main_memset и va_main_fgets, чтобы считать
несколько payload-ов.  Адреса обозначены на листинге (листинг 2.3):
```c
// main:
// ...
    // ADDR: va_main_memset
	memset(command_buf, 0, 0x400u);
    // ADDR: va_main_fgets
	fgets(command_buf, 1024, stdin);
	for ( i = 0; i < strlen(command_buf); ++i )
	// perform operation from user input in cycle
    do_brainfuck(command_buf[i]);
// ...
```
```asm
Dump of assembler code for function main:
;...
va_main_memset:
0x08048700 <+143>:   mov    DWORD PTR [esp+0x8],0x400
0x08048708 <+151>:   mov    DWORD PTR [esp+0x4],0x0
0x08048710 <+159>:   lea    eax,[esp+0x2c]
0x08048714 <+163>:   mov    DWORD PTR [esp],eax
0x08048717 <+166>:   call   0x80484c0 <memset@plt>
va_main_fgets:
0x0804871c <+171>:   mov    eax,ds:0x804a040
0x08048721 <+176>:   mov    DWORD PTR [esp+0x8],eax
0x08048725 <+180>:   mov    DWORD PTR [esp+0x4],0x400
0x0804872d <+188>:   lea    eax,[esp+0x2c]
0x08048731 <+192>:   mov    DWORD PTR [esp],eax
0x08048734 <+195>:   call   0x8048450 <fgets@plt>
;...
```
Индексы в таблице GOT говорят сами за себя, таблица уже приводилась в листинге
2.1. Адреса глобальных переменных взяты оттуда же.

va_reloc_arg и va_reloc_arg2 - адреса wrapper_fixup'ов, с reloc_arg 0x8 и 0x10
взяты из секции с @plt трамплинами (листинг 2.4):
```asm
0x08048450 <fgets@plt+0>:    jmp    DWORD PTR ds:0x804a010
va_reloc_arg: 
0x08048456 <fgets@plt+6>:    push   0x8
0x0804845b <fgets@plt+11>:   jmp    0x8048430
0x08048460 <__stack_chk_fail@plt+0>: jmp    DWORD PTR ds:0x804a014
va_reloc_arg2:
0x08048466 <__stack_chk_fail@plt+6>: push   0x10
0x0804846b <__stack_chk_fail@plt+11>:        jmp    0x8048430
```
Дальше создается Generator и payload'ы, все с комментариями. Нужно учитывать,
в комментариях описываются действия payload'ов, которые происходят только после
их отправки (p.sendline(payload)).

Экплуатация разделяется на большее число этапов (мы больше раз возвращаемся в
main из do_brainfuck), чем в стандартном способе. Это связано прежде всего с
большей длиной генерируемых данных - fake_link_map. Можно было бы
оптимизировать записи, но возврат в main не вызывает трудностей.

Как мы уже упоминали, структура fake_link_map строится специальным образом с
помощью функции gen_link_map_32:

    fake_link_map.getName(0x10) == 'gets'
    fake_link_map.getName(0x8) == 'system'

Как и в стандартном способе, наша цель - превратить пару (memset, fgets) в
(gets, system).  После первого вызова (memset, fgets) GOT имеет вид (только
интересующие нас поля):
```asm
index | address   --> points to (description)
1     | 0x804a004 --> &old_link_map
...
4     | 0x804a010 --> 0xf76132a0 (<fgets>)
...
11    | 0x804a02c --> 0xf76d9af0 (<memset>)
12    | 0x804a030 --> 0x80484d6  (<putchar@plt+6>: push   0x48)
```
Mодифицируем таблицу GOT следующим образом:
```asm
1    | 0x804a004 --> &new_link_map
...   
4    | 0x804a010 --> 0x8048456 (<fgets@plt+6>:   push   0x8)
...   
11   | 0x804a02c --> 0x8048466 (<__stack_chk_fail@plt+6>:    push   0x10)
12   | 0x804a030 --> 0x8048700 (<main+143>:      mov    DWORD PTR [esp+0x8],0x400)
```
То есть, мы заменили значение GOT[1] на &new_link_map, вместо GOT[MEMSET] и
GOT[FGETS] записали wrapper_fixup(0x10), wrapper_fixup(0x8) соответственно,
GOT[PUTCHAR] указывает на &main_143 для возврата в функцию main.

Ключевые зависимости нового способа:
* чтение значения из GOT (memory-leak)
* запись по известному адресу (memory-write)
* контроль eip (в данном случае - перезапись GOT[PUTCHAR] и GOT[X])

Замечание: переписывать GOT[X] в общем случае не обязательно: функцию-трамплин
можно вызывать не только из plt-заглушек.  Адрес функции-трамплина
trampoline_fixup хранится в GOT[2], прыжок на который осуществляется в plt[0]
заглушке (по адресу plt[0] + 6). Поэтому можно вызвать trampoline_fixup,
положив указатель на fake_link_map на стэк и вызывав plt[0]+6
```asm
<plt[0]>:         push   DWORD PTR GOT[1] ; link_map
<plt[0] + 6>:     jmp    DWORD PTR GOT[2] ; trampoline_fixup
```
### Итоги

Основная разница, как уже отмечалось выше - способ обхода ASLR.
В стандартном способе есть доступ к файлу libc, и адрес загрузки libc
вычисляется с помощью memory-leak адреса из GOT таблицы.  Это удобно, если есть
доступ к libc.  
return_to_libc позволяет получить адреса нужных функций независимо от версии
libc. То есть можно использовать эту технику, если нет доступа к libc, или
требуется более надежный, не зависящий от версии libc эксплоит.
Существенный минус техники - необходим memory-write по известному адресу.
В итоге, выбор техники зависит от того, что проще: осуществить memory-write или
получить доступ к версии libc.
