SECTIONS
{
    .text :
    {
        *(.begin);
        *(.text);
        *(.text.*);
        *(.rodata.*);
        *(.bss.*);
        *(.end);
    }
}