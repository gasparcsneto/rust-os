/* Layout de memória do kernel aarch64.
 *
 * No x86 o crate `bootloader` decide onde o kernel mora. No ARM não existe
 * equivalente: seguimos o *protocolo de boot do arm64*, documentado pelo
 * kernel Linux em `Documentation/arch/arm64/booting.rst`. Quem carrega a
 * imagem (QEMU, U-Boot ou firmware UEFI) lê um cabeçalho de 64 bytes no
 * início dela e a deposita em `base_da_RAM + text_offset`.
 *
 * A máquina `virt` do QEMU põe a RAM em 0x4000_0000 e usamos text_offset de
 * 0x8_0000, então o kernel é carregado em 0x4008_0000 — que é exatamente o
 * endereço para onde linkamos aqui. Os dois precisam concordar.
 */

ENTRY(_start)

SECTIONS
{
    . = 0x40080000;
    __image_start = .;

    .text : ALIGN(4096) {
        /* KEEP impede o linker de descartar o código de boot: nada em Rust o
         * referencia, então sem isso a otimização de seções o eliminaria e o
         * kernel não teria ponto de entrada nem cabeçalho de imagem. */
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .data   : ALIGN(4096) { *(.data .data.*) }

    .bss : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)

        /* A pilha mora dentro do .bss de propósito: assim ela é contabilizada
         * no layout, zerada junto com o resto e não corre o risco de colidir
         * com dados do kernel. */
        . = ALIGN(16);
        /* Canário: uma palavra logo abaixo da pilha, com valor conhecido.
         *
         * No x86 o bootloader instala uma guard page de verdade — uma página
         * desmapeada que faz o estouro virar falha na hora. Aqui a pilha mora
         * dentro de um bloco de identidade de 1 GiB, e desmapear 4 KiB de
         * dentro dele exigiria fatiar o bloco, o que o mapeador recusa de
         * propósito.
         *
         * O canário não detecta o estouro no instante em que acontece, mas
         * detecta que aconteceu — e sem ele um estouro corromperia os `static`
         * do kernel (o anel de log, o estado do alocador) em silêncio
         * absoluto. */
        __stack_canary = .;
        . += 16;
        __stack_bottom = .;
        . += 0x20000;          /* 128 KiB */
        __stack_top = .;

        . = ALIGN(16);
        __bss_end = .;
    }

    __image_end = .;

    /* O cabeçalho de imagem precisa declarar o tamanho *efetivo*, incluindo o
     * .bss — é assim que quem carrega sabe quanta RAM reservar depois do fim
     * do arquivo, que é menor porque o .bss não ocupa bytes em disco. */
    __image_size = __image_end - __image_start;

    /* Sem tabelas de unwinding: o kernel usa panic=abort e nunca desenrola a
     * pilha, então carregá-las seria peso morto na imagem. */
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.eh_frame_hdr) }
}
