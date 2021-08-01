SECTIONS
{
    .text :
    {
        *(.text);
        *(.text.*);
        *(.rodata.*);
        *(.bss.*);
    }
}