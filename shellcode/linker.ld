SECTIONS
{
    .text :
    {
        *(.begin);
        *(.text.*);
        *(.rodata.*);
        *(.end);
    }
}