import Foundation

/// Tudo que precisa sobreviver entre sessões.
struct SaveData: Codable, Sendable {
    /// Dinheiro na carteira do jogador.
    var money = 0
    /// Zonas do mapa já liberadas.
    var unlockedZones: Set<Int> = [0]
    /// Obstáculos já removidos (ids de `WorldLayout.obstacles`).
    var destroyedObstacles: Set<String> = []
    /// Vida restante dos obstáculos parcialmente cortados.
    var obstacleHealth: [String: Float] = [:]
    /// Nível comprado de cada pad (chave = `PadKind.rawValue`).
    var padLevels: [String: Int] = [:]
    /// Pagamento parcial do nível atual de cada pad.
    var padPaid: [String: Int] = [:]
    /// Estoque sobre o balcão (chave = `ItemKind.rawValue`).
    var counterStock: [String: Int] = [:]
    /// Estoque das bandejas das construções (chave = nome da bandeja, ex.: "coop.wheat").
    var trayStock: [String: Int] = [:]
    /// Itens na pilha das costas do jogador, de baixo para cima (`ItemKind.rawValue`).
    var carried: [String] = []
    /// Dinheiro ainda no tapete.
    var cashOnMat = 0
    /// Marcos do tutorial.
    var didMove = false
    var didHarvest = false
    var didSell = false
    var didCollectCash = false
    /// Preferência de som.
    var soundOn = true

    /// Declaradas à mão porque a leitura (logo abaixo) é escrita à mão.
    /// Ao criar um campo novo, acrescente-o aqui e em `init(from:)`.
    private enum CodingKeys: String, CodingKey {
        case money, unlockedZones, destroyedObstacles, obstacleHealth, padLevels, padPaid
        case counterStock, trayStock, carried, cashOnMat
        case didMove, didHarvest, didSell, didCollectCash, soundOn
    }
}

extension SaveData {
    /// Leitura tolerante: campo que não existe no arquivo fica com o valor padrão.
    /// Assim, acrescentar um campo novo numa atualização não apaga o progresso de quem já joga
    /// (com o `Codable` automático, um campo ausente faz a leitura inteira falhar).
    init(from decoder: any Decoder) throws {
        self.init()
        let box = try decoder.container(keyedBy: CodingKeys.self)
        money = try box.decodeIfPresent(Int.self, forKey: .money) ?? money
        money = max(0, money)
        unlockedZones = try box.decodeIfPresent(Set<Int>.self, forKey: .unlockedZones) ?? unlockedZones
        unlockedZones.insert(0)
        destroyedObstacles = try box.decodeIfPresent(Set<String>.self, forKey: .destroyedObstacles) ?? destroyedObstacles
        obstacleHealth = try box.decodeIfPresent([String: Float].self, forKey: .obstacleHealth) ?? obstacleHealth
        padLevels = try box.decodeIfPresent([String: Int].self, forKey: .padLevels) ?? padLevels
        padPaid = try box.decodeIfPresent([String: Int].self, forKey: .padPaid) ?? padPaid
        counterStock = try box.decodeIfPresent([String: Int].self, forKey: .counterStock) ?? counterStock
        trayStock = try box.decodeIfPresent([String: Int].self, forKey: .trayStock) ?? trayStock
        carried = try box.decodeIfPresent([String].self, forKey: .carried) ?? carried
        cashOnMat = try box.decodeIfPresent(Int.self, forKey: .cashOnMat) ?? cashOnMat
        cashOnMat = max(0, cashOnMat)
        didMove = try box.decodeIfPresent(Bool.self, forKey: .didMove) ?? didMove
        didHarvest = try box.decodeIfPresent(Bool.self, forKey: .didHarvest) ?? didHarvest
        didSell = try box.decodeIfPresent(Bool.self, forKey: .didSell) ?? didSell
        didCollectCash = try box.decodeIfPresent(Bool.self, forKey: .didCollectCash) ?? didCollectCash
        soundOn = try box.decodeIfPresent(Bool.self, forKey: .soundOn) ?? soundOn
    }
}
