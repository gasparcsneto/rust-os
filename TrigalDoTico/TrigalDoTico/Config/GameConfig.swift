import Foundation

/// Arquivo único de balanceamento.
/// Tudo que é preço, velocidade, capacidade ou tempo do jogo mora aqui.
/// Unidades: metros, segundos e "moedas" (a menos que o comentário diga outra coisa).
enum GameConfig {

    // MARK: - Controles

    enum Controls {
        /// Raio do joystick em pontos de tela. Arrastar até a borda = velocidade máxima.
        static let joystickRadius: Double = 64
        /// Fração do raio abaixo da qual o arraste é ignorado (evita tremedeira).
        static let deadZone: Float = 0.08
    }

    // MARK: - Jogador

    enum Player {
        /// Velocidade máxima de caminhada sem upgrades (m/s).
        static let baseSpeed: Float = 4.4
        /// Ganho de velocidade por nível do pad "Botas".
        static let speedPerBootsLevel: Float = 0.45
        /// Raio de colisão do personagem.
        static let radius: Float = 0.35
        /// Quão rápido o personagem gira para a direção do movimento (maior = mais seco).
        static let turnSharpness: Float = 14
        /// Itens que cabem na pilha das costas no início do jogo.
        static let baseCapacity = 20
        /// Posição inicial (x, z).
        static let startPosition = SIMD2<Float>(-2.6, 1.4)
    }

    // MARK: - Foice (colheita do jogador)

    enum Sickle {
        /// Raio de corte no nível 0.
        static let baseRadius: Float = 0.95
        /// Raio extra por nível de "Melhorar foice".
        static let radiusPerLevel: Float = 0.2
        /// Intervalo entre golpes no nível 0.
        static let baseInterval: Float = 0.06
        /// O intervalo é multiplicado por este fator a cada nível (menor = mais rápido).
        static let intervalFactorPerLevel: Float = 0.85
        /// Quantas espigas um golpe do jogador pode cortar.
        static let cropsPerSwing = 2
        /// Preço de cada nível do pad "Melhorar foice".
        static let prices = [50, 74, 100, 135, 180]
    }

    // MARK: - Plantação

    enum Crops {
        /// Distância entre pés de trigo.
        static let spacing: Float = 0.6
        /// Tempo para o trigo cortado voltar a ficar maduro.
        static let regrowTime: Float = 10
        /// O tempo de rebrota é multiplicado por este fator a cada nível de "Regador".
        static let regrowFactorPerWateringLevel: Float = 0.8
    }

    // MARK: - Pilha nas costas

    enum Stack {
        /// Altura de cada item na pilha.
        static let step: Float = 0.18
        /// Itens por coluna; acima disso a pilha abre uma segunda coluna atrás.
        static let itemsPerColumn = 20
        /// Distância entre colunas.
        static let columnSpacing: Float = 0.4
        /// Quanto o topo da pilha se desloca por unidade de balanço.
        static let swayReach: Float = 1.0
        /// Mola do balanço: rigidez e amortecimento.
        static let swayStiffness: Float = 60
        static let swayDamping: Float = 7
        /// Balanço alvo por m/s de velocidade (a pilha "fica para trás").
        static let swayPerSpeed: Float = 0.1
    }

    // MARK: - Voo dos itens

    enum Flight {
        /// Duração padrão do arco.
        static let duration: Float = 0.36
        /// Altura padrão do arco.
        static let arcHeight: Float = 1.3
    }

    // MARK: - Balcão

    enum Counter {
        /// Estoque máximo de cada ponto de entrega.
        static let slotCapacity = 40
        /// Intervalo entre itens saindo da pilha para o balcão.
        static let transferInterval: Float = 0.07
        /// Distância em que a entrega começa.
        static let slotRadius: Float = 1.7
        /// Quantos itens aparecem empilhados no balcão (o resto é só número).
        static let maxVisible = 16
    }

    // MARK: - Clientes

    enum Customers {
        /// Preço de venda de cada produto, por unidade.
        static func basePrice(_ kind: ItemKind) -> Int {
            switch kind {
            case .wheat: return 2
            case .egg: return 6
            case .pie: return 15
            default: return 0
            }
        }

        /// Quantas unidades um cliente pode pedir.
        static func wantedRange(_ kind: ItemKind) -> ClosedRange<Int> {
            switch kind {
            case .wheat: return 2...5
            case .egg: return 1...3
            default: return 1...2
            }
        }

        /// Intervalo médio entre clientes novos de cada fila.
        static let spawnInterval: Float = 2.4
        /// Tamanho máximo de cada fila.
        static let maxQueue = 5
        /// Velocidade de caminhada dos clientes.
        static let walkSpeed: Float = 2.3
        /// Intervalo entre unidades entregues ao cliente da frente.
        static let serveInterval: Float = 0.14
        /// Distância entre pessoas na fila.
        static let queueSpacing: Float = 0.95
        /// Bônus de preço por nível do pad "Promoção" (0.25 = +25%).
        static let promoBonusPerLevel: Float = 0.25
    }

    // MARK: - Dinheiro

    enum Cash {
        /// Intervalo entre notas voando do tapete para o jogador.
        static let collectInterval: Float = 0.035
        /// Fração do monte recolhida a cada nota (faz montes grandes sumirem rápido).
        static let collectFraction: Float = 0.18
        /// Quantas moedas cada nota visível do tapete representa.
        static let unitsPerNote = 3
        /// Máximo de notas desenhadas no tapete.
        static let maxNotesVisible = 48
        /// Distância em que a coleta começa.
        static let matRadius: Float = 1.05
        /// Máximo de notas que voam do balcão por venda.
        static let notesPerSale = 5
    }

    // MARK: - Obstáculos

    enum Obstacles {
        /// "Vida" removida por segundo no nível 0 da foice.
        static let baseDPS: Float = 110
        /// Dano extra por segundo a cada nível da foice.
        static let dpsPerSickleLevel: Float = 30
        /// Distância máxima para cortar.
        static let reach: Float = 1.9
        /// O jogador precisa estar abaixo desta velocidade ("parado") para cortar.
        static let stillSpeed: Float = 0.6
        /// Intervalo entre batidas (som, lascas e haptic).
        static let hitInterval: Float = 0.22
    }

    // MARK: - Pads de compra

    enum Pads {
        /// Lado do quadrado no chão.
        static let size: Float = 1.7
        /// Tempo parado em cima do pad antes de o pagamento começar. Evita gastar dinheiro
        /// só por atravessar um pad e dá uma pausa entre um nível e o próximo.
        static let startDelay: Float = 0.3
        /// Tempo para pagar um pad inteiro ficando em cima dele.
        static let payDuration: Float = 1.4
        /// Velocidade mínima de pagamento (moedas/s), para pads baratos não demorarem.
        static let minPayRate: Float = 25
        /// Intervalo mínimo entre avisos de "SEM DINHEIRO".
        static let warnCooldown: Float = 1.6
    }

    // MARK: - Ajudantes

    enum Helpers {
        /// Preço de cada ajudante (a quantidade de preços define o máximo: 4).
        static let prices = [30, 60, 110, 180]
        static let baseSpeed: Float = 2.6
        /// Velocidade extra por nível de "Treinar ajudantes".
        static let speedPerTrainingLevel: Float = 0.4
        static let baseCapacity = 6
        /// Capacidade extra por nível de "Treinar ajudantes".
        static let capacityPerTrainingLevel = 2
        static let harvestRadius: Float = 0.75
        static let harvestInterval: Float = 0.32
    }

    // MARK: - Galinheiro

    enum Coop {
        static let price = 150
        /// Trigo consumido por ovo.
        static let wheatPerEgg = 2
        /// Tempo para produzir um ovo.
        static let interval: Float = 1.5
        static let inputCapacity = 20
        static let outputCapacity = 12
    }

    // MARK: - Padaria

    enum Bakery {
        static let price = 400
        /// Ingredientes por torta.
        static let wheatPerPie = 2
        static let eggsPerPie = 1
        /// Tempo para assar uma torta.
        static let interval: Float = 2.4
        static let inputCapacity = 20
        static let outputCapacity = 10
    }

    // MARK: - Celeiro

    enum Barn {
        static let price = 300
        /// Capacidade extra da pilha ao construir o celeiro.
        static let capacityOnBuild = 10
        /// Preço de cada ampliação.
        static let upgradePrices = [350, 500, 700]
        /// Capacidade extra por ampliação.
        static let capacityPerUpgrade = 10
    }

    // MARK: - Upgrades das expansões

    enum Upgrades {
        /// "Regador": trigo cresce mais rápido.
        static let wateringPrices = [180, 300, 450]
        /// "Botas": jogador anda mais rápido.
        static let bootsPrices = [200, 320, 480]
        /// "Forno turbo": galinheiro e padaria produzem mais rápido.
        static let ovenPrices = [300, 450, 650]
        /// Aumento de velocidade de produção por nível (0.3 = +30%).
        static let ovenSpeedPerLevel: Float = 0.3
        /// "Treinar ajudantes".
        static let trainingPrices = [260, 400, 600]
        /// "Promoção": clientes pagam mais.
        static let promoPrices = [350, 550, 800]
    }

    // MARK: - Câmera

    enum Camera {
        /// Campo de visão vertical (graus). Valor baixo = aparência mais isométrica.
        static let fieldOfView: Float = 40
        /// Distância da câmera até o jogador.
        static let distance: Float = 23
        /// Inclinação para baixo (graus).
        static let pitchDegrees: Float = 52
        /// Suavidade do acompanhamento (maior = câmera mais colada).
        static let followSharpness: Float = 5
        /// Desloca o foco para o norte, mostrando mais mapa acima do jogador.
        static let focusOffsetZ: Float = -1.0
    }

    // MARK: - Visual e desempenho

    enum Visual {
        /// Intensidade da luz direcional (lux).
        static let sunIntensity: Float = 2200
        /// Limite de partículas simultâneas (palha e lascas).
        static let maxParticles = 70
    }

    // MARK: - Persistência

    enum Persistence {
        /// Intervalo do salvamento automático.
        static let autosaveInterval: Float = 5
    }
}
