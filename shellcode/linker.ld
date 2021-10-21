SECTIONS
{
    .text ALIGN(0x1000):
    {
        *(.entry);
        *(.text);
        *(.text.*);
        *(.rodata.*);
        *(.bss.*);
    }
}