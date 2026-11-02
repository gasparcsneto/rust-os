/*
 * O mapa de um programa de usuário do Duke.
 *
 * Três segmentos, um por permissão, cada um começando numa página própria:
 * o carregador do kernel recusa dois segmentos na mesma página, porque
 * permissão é da página e a única negociação segura seria a união — que é
 * como se perde o W^X.
 *
 * O endereço de partida é `protocolo::usuario::BASE`, repetido aqui porque
 * um script de ligação não inclui Rust. Quem confere que os dois não
 * divergiram é o `cargo xtask elf`, que lê o executável pronto.
 */

ENTRY(_start)

PHDRS
{
    codigo  PT_LOAD FLAGS(5);   /* leitura e execução */
    leitura PT_LOAD FLAGS(4);   /* só leitura */
    dados   PT_LOAD FLAGS(6);   /* leitura e escrita */
    notas   PT_NOTE FLAGS(4);   /* o manifesto — ver `programas::manifesto` */
}

SECTIONS
{
    . = 0x100000000;

    .text : {
        *(.text.inicio)
        *(.text .text.*)
    } :codigo

    . = ALIGN(4096);
    .rodata : {
        *(.rodata .rodata.* .lrodata .lrodata.*)
    } :leitura

    /* O manifesto: no segmento de leitura, e também no `PT_NOTE`, que é
     * onde o kernel o procura. Antes do descarte abaixo, que leva as outras
     * notas: a primeira regra que casa é a que vale. */
    .note.duke : {
        KEEP(*(.note.duke.manifesto))
    } :leitura :notas

    . = ALIGN(4096);
    .data : {
        *(.data .data.* .ldata .ldata.*)
        *(.got .got.*)
    } :dados
    .bss : {
        *(.bss .bss.* .lbss .lbss.*)
        *(COMMON)
    } :dados

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
