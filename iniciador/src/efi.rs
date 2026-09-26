//! As tabelas e os protocolos da UEFI, declarados à mão.
//!
//! # Por que à mão, e não por um crate
//!
//! Porque o ponto desta peça é **não** depender de um bootloader de
//! terceiros, e trocar o `bootloader` por um `uefi` seria trocar uma
//! dependência por outra no lugar exato onde este projeto quer saber o que
//! está acontecendo.
//!
//! O que está aqui é a categoria que este projeto já escreve à mão em todo
//! lugar: **protocolo e estrutura**. Não há aritmética de bits a acertar, não
//! há palavra de configuração a montar — há um layout de struct C descrito
//! num documento público, e declará-lo em Rust é transcrição, não invenção.
//!
//! # Como um erro de transcrição aparece
//!
//! É a pergunta que importa, porque um campo no deslocamento errado não dá
//! erro de compilação. Três coisas o denunciam, e as três são conferidas em
//! [`crate::relatorio`] antes de qualquer ponteiro ser chamado:
//!
//! 1. **A assinatura.** Cada uma das três tabelas carrega uma constante de
//!    oito bytes no começo. Ler a do meio errado dá lixo.
//! 2. **O CRC-32 do cabeçalho.** O firmware o calculou sobre os bytes da
//!    tabela; nós o recalculamos. Ele confere o tamanho e o conteúdo do
//!    cabeçalho contra o que o firmware escreveu.
//! 3. **A revisão.** Um número com maior e menor, que tem de fazer sentido
//!    como versão da UEFI — 2.x, e não 0x4141.
//!
//! As três juntas não provam que o campo número trinta está certo. O que
//! prova isso é chamá-lo e ver o que volta, e é por isso que o relatório
//! imprime o resultado de cada chamada em vez de só dizer que ela retornou.

use core::ffi::c_void;

/// O tipo de retorno de toda função da UEFI.
///
/// Zero é sucesso. O bit mais alto ligado marca erro — é assim que a UEFI
/// distingue erro de aviso sem um segundo canal, e é a mesma ideia do
/// negativo nas chamadas de sistema do Duke.
pub type Status = usize;

pub const SUCESSO: Status = 0;

/// O bit que marca um `Status` como erro.
pub const BIT_DE_ERRO: Status = 1 << (usize::BITS - 1);

/// Se um `Status` é erro.
pub fn deu_errado(status: Status) -> bool {
    status & BIT_DE_ERRO != 0
}

/// O erro "o buffer que você deu é pequeno demais".
///
/// Não é uma falha: é como a UEFI responde a pergunta "de que tamanho
/// precisa?", devolvendo o tamanho junto. Quem chama `GetMemoryMap` o recebe
/// na primeira tentativa por construção.
pub const BUFFER_PEQUENO: Status = BIT_DE_ERRO | 5;

pub type Handle = *mut c_void;

/// Um identificador de protocolo.
///
/// O formato é o de um GUID da Microsoft: os três primeiros campos em
/// little-endian, os oito bytes finais na ordem em que aparecem escritos. É
/// por isso que `9042a9de-23dc-4a38-96fb-7aded080516a` vira
/// `(0x9042a9de, 0x23dc, 0x4a38, [0x96, 0xfb, ...])` e não uma sequência de
/// dezesseis bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    pub a: u32,
    pub b: u16,
    pub c: u16,
    pub d: [u8; 8],
}

/// O cabeçalho comum das três tabelas da UEFI.
#[repr(C)]
pub struct Cabecalho {
    pub assinatura: u64,
    pub revisao: u32,
    pub tamanho: u32,
    pub crc32: u32,
    pub reservado: u32,
}

/// `IBI SYST`, em little-endian.
pub const ASSINATURA_DO_SISTEMA: u64 = 0x5453_5953_2049_4249;
/// `BOOTSERV`.
pub const ASSINATURA_DOS_SERVICOS_DE_BOOT: u64 = 0x5652_4553_544f_4f42;
/// `RUNTSERV`.
pub const ASSINATURA_DOS_SERVICOS_DE_EXECUCAO: u64 = 0x5652_4553_544e_5552;

/// A tabela que o firmware entrega no segundo argumento de `efi_main`.
///
/// É a raiz de tudo: dela saem os dois conjuntos de serviços e o console.
#[repr(C)]
pub struct Sistema {
    pub cabecalho: Cabecalho,
    /// O nome do firmware, em UTF-16 terminado em zero.
    pub fabricante: *const u16,
    pub revisao_do_firmware: u32,
    _entrada_do_console: Handle,
    _entrada: *mut c_void,
    _saida_do_console: Handle,
    pub saida: *mut SaidaDeTexto,
    _erro_do_console: Handle,
    _erro: *mut c_void,
    pub execucao: *mut ServicosDeExecucao,
    pub boot: *mut ServicosDeBoot,
    pub quantas_configuracoes: usize,
    pub configuracoes: *const c_void,
}

/// O console de texto do firmware.
///
/// Só o suficiente para escrever: o resto do protocolo — cores, cursor, modos
/// — não tem uso aqui, e declarar campos que ninguém chama seria descrever
/// capacidade que este programa não tem.
#[repr(C)]
pub struct SaidaDeTexto {
    _reiniciar: *const c_void,
    pub escrever: unsafe extern "efiapi" fn(*mut SaidaDeTexto, *const u16) -> Status,
    _resto: [*const c_void; 8],
}

/// Os serviços que só existem antes de o kernel assumir a máquina.
///
/// **Todos** os ponteiros de função estão declarados, inclusive os que este
/// programa nunca chama. É o que mantém os deslocamentos honestos: pular os
/// que não interessam exigiria contar bytes à mão, e um erro de contagem
/// chamaria a função errada — que numa tabela de funções com assinaturas
/// diferentes é um salto para o lugar errado, não um erro de tipo.
#[repr(C)]
pub struct ServicosDeBoot {
    pub cabecalho: Cabecalho,

    // Prioridade de tarefa.
    _elevar_tpl: *const c_void,
    _restaurar_tpl: *const c_void,

    // Memória.
    pub alocar_paginas: unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    _liberar_paginas: *const c_void,
    pub mapa_de_memoria:
        unsafe extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> Status,
    pub alocar_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut u8) -> Status,
    pub liberar_pool: unsafe extern "efiapi" fn(*mut u8) -> Status,

    // Eventos e temporizadores.
    _criar_evento: *const c_void,
    _programar_temporizador: *const c_void,
    _esperar_evento: *const c_void,
    _sinalizar_evento: *const c_void,
    _fechar_evento: *const c_void,
    _conferir_evento: *const c_void,

    // Protocolos.
    _instalar_protocolo: *const c_void,
    _reinstalar_protocolo: *const c_void,
    _desinstalar_protocolo: *const c_void,
    pub protocolo_do_handle:
        unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    _reservado: *const c_void,
    _registrar_notificacao: *const c_void,
    _localizar_handle: *const c_void,
    _localizar_caminho: *const c_void,
    _instalar_configuracao: *const c_void,

    // Imagens.
    _carregar_imagem: *const c_void,
    _iniciar_imagem: *const c_void,
    _sair: *const c_void,
    _descarregar_imagem: *const c_void,
    pub sair_dos_servicos_de_boot: unsafe extern "efiapi" fn(Handle, usize) -> Status,

    // Diversos.
    _contador_monotonico: *const c_void,
    _esperar: *const c_void,
    _cao_de_guarda: *const c_void,

    // Drivers.
    _conectar_controlador: *const c_void,
    _desconectar_controlador: *const c_void,

    // Abrir e fechar protocolo.
    _abrir_protocolo: *const c_void,
    _fechar_protocolo: *const c_void,
    _informacao_de_protocolo: *const c_void,

    // Biblioteca.
    _protocolos_por_handle: *const c_void,
    _localizar_handles: *const c_void,
    pub localizar_protocolo:
        unsafe extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
    _instalar_varios: *const c_void,
    _desinstalar_varios: *const c_void,

    // CRC-32.
    pub calcular_crc32: unsafe extern "efiapi" fn(*const u8, usize, *mut u32) -> Status,

    // Mais diversos.
    _copiar_memoria: *const c_void,
    _preencher_memoria: *const c_void,
    _criar_evento_ex: *const c_void,
}

/// Os serviços que continuam existindo depois que o kernel assume.
///
/// Deste conjunto só interessa desligar a máquina: é como o iniciador
/// encerra uma execução de diagnóstico sem deixar o emulador pendurado.
#[repr(C)]
pub struct ServicosDeExecucao {
    pub cabecalho: Cabecalho,
    _hora: *const c_void,
    _definir_hora: *const c_void,
    _hora_de_despertar: *const c_void,
    _definir_despertar: *const c_void,
    _mapa_virtual: *const c_void,
    _converter_ponteiro: *const c_void,
    _variavel: *const c_void,
    _proxima_variavel: *const c_void,
    _definir_variavel: *const c_void,
    _contador_alto: *const c_void,
    pub reiniciar: unsafe extern "efiapi" fn(u32, Status, usize, *const c_void) -> !,
}

/// O que `ResetSystem` faz: desligar.
pub const DESLIGAR: u32 = 2;

/// Um descritor do mapa de memória.
///
/// O mapa é um vetor destes — mas **não** com este passo. A UEFI devolve o
/// tamanho de cada descritor junto com o mapa, e ele pode ser maior que esta
/// struct: o firmware tem direito de acrescentar campos no fim.
///
/// **Não é hipótese.** O EDK II que roda aqui declara descritores de 48
/// bytes, e esta struct tem 40. Percorrer de `size_of` em `size_of` sairia do
/// compasso no segundo descritor e leria o mapa inteiro deslocado — com
/// números plausíveis, porque os campos vizinhos também são endereços e
/// contagens.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Descritor {
    pub tipo: u32,
    _preenchimento: u32,
    pub fisico: u64,
    pub virtual_: u64,
    pub paginas: u64,
    pub atributos: u64,
}

/// Os tipos de memória que interessam a quem vai assumir a máquina.
pub mod memoria {
    /// Memória livre, que o kernel pode usar para o que quiser.
    pub const CONVENCIONAL: u32 = 7;
    /// Código e dados do próprio iniciador.
    pub const CODIGO_DO_CARREGADOR: u32 = 1;
    pub const DADOS_DO_CARREGADOR: u32 = 2;
    /// Do firmware, e livre depois de `ExitBootServices`.
    pub const CODIGO_DE_BOOT: u32 = 3;
    pub const DADOS_DE_BOOT: u32 = 4;
}

/// O tamanho de uma página da UEFI. Sempre 4 KiB, em toda arquitetura.
pub const PAGINA: u64 = 4096;

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL`.
pub const GUID_DO_VIDEO: Guid = Guid {
    a: 0x9042_a9de,
    b: 0x23dc,
    c: 0x4a38,
    d: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};

#[repr(C)]
pub struct Video {
    _consultar_modo: *const c_void,
    _definir_modo: *const c_void,
    _transferir: *const c_void,
    pub modo: *const ModoDeVideo,
}

#[repr(C)]
pub struct ModoDeVideo {
    pub quantos_modos: u32,
    pub modo_atual: u32,
    pub informacao: *const InformacaoDeVideo,
    pub tamanho_da_informacao: usize,
    pub buffer: u64,
    pub tamanho_do_buffer: usize,
}

#[repr(C)]
pub struct InformacaoDeVideo {
    pub versao: u32,
    pub largura: u32,
    pub altura: u32,
    pub formato: u32,
    pub mascaras: [u32; 4],
    pub pixels_por_linha: u32,
}

/// Os formatos de pixel que a UEFI descreve.
pub mod formato {
    /// Vermelho, verde, azul, reservado — um byte cada.
    pub const RGB: u32 = 0;
    /// Azul, verde, vermelho, reservado.
    pub const BGR: u32 = 1;
    /// Descrito por máscaras de bits, que este iniciador não interpreta.
    pub const MASCARAS: u32 = 2;
    /// Sem buffer alcançável: só a operação de transferência.
    pub const SO_TRANSFERENCIA: u32 = 3;
}
