SECTIONS
{
    .text :
    {
        *(.entry);
        *(.text);
        *(.text.*);
        *(.rodata.*);
        *(.bss.*);
    }
}