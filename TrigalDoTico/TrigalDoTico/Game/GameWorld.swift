import RealityKit
import UIKit
import simd

/// Círculo sólido no chão (construções).
struct Collider {
    var center: Vec2
    var radius: Float
}

/// Destino atual da seta de objetivo.
struct Objective {
    var position: Vec3
    /// Altura em que a seta 3D flutua sobre o alvo.
    var height: Float
}

/// Recursos compartilhados do jogo (o equivalente aos "resources" de um ECS):
/// referências de cena, pools, save, entrada do joystick e valores derivados de upgrades.
/// Os Systems leem e escrevem aqui; a lógica de quadro a quadro fica neles.
@MainActor
final class GameWorld {

    static let shared = GameWorld()

    /// O mundo, se já estiver montado. Os Systems usam isto para não rodar antes da hora.
    static var ready: GameWorld? { shared.isReady ? shared : nil }

    // MARK: Recursos

    let state = GameState()
    let audio = AudioManager()
    let haptics = Haptics()
    var pool = EntityPool()
    var save: SaveData

    // MARK: Cena

    weak var arView: ARView?
    let anchor = AnchorEntity(world: SIMD3<Float>(0, 0, 0))
    var root = Entity()
    let cameraEntity = PerspectiveCamera()
    private(set) var isReady = false

    // MARK: Entrada

    /// Vetor do joystick em espaço de tela, cada eixo em -1…1 (y positivo = para baixo).
    var input: Vec2 = .zero

    // MARK: Entidades importantes

    var player: Entity?
    var sickle: Entity?
    var helpers: [Entity] = []
    var slotPiles: [ItemKind: Entity] = [:]
    var cashPile: Entity?
    /// Bandejas das construções, pela chave usada no save (ex.: "coop.wheat").
    var trayPiles: [String: Entity] = [:]
    var pads: [PadKind: Entity] = [:]
    var obstacles: [String: Entity] = [:]
    var zoneCovers: [Int: Entity] = [:]
    var barnModel: Entity?
    var targetArrow: Entity?
    var groundArrow: Entity?

    // MARK: Plantação (vetores paralelos, indexados por `CropComponent.index`)

    var crops: [Entity] = []
    var cropPositions: [Vec2] = []
    var cropRipe: [Bool] = []
    /// Índices dos pés de trigo em rebrota.
    var growing: [Int] = []

    // MARK: Navegação

    var walkRects: [Rect2] = []
    var colliders: [Collider] = []

    // MARK: Clientes

    var queues: [ItemKind: [Entity]] = [:]
    var leaving: [Entity] = []
    var freeCustomers: [Entity] = []
    var spawnTimers: [ItemKind: Float] = [:]
    var customerRandom = SeededRandom(seed: 2024)

    // MARK: Valores derivados dos upgrades (recalculados em `applyUpgrades`)

    var playerSpeed: Float = GameConfig.Player.baseSpeed
    var helperSpeed: Float = GameConfig.Helpers.baseSpeed
    var regrowTime: Float = GameConfig.Crops.regrowTime
    var productionSpeed: Float = 1
    var priceMultiplier: Float = 1
    var obstacleDPS: Float = GameConfig.Obstacles.baseDPS

    // MARK: Diversos

    var time: Float = 0
    var autosaveTimer: Float = 0
    var activeParticles = 0
    /// Dinheiro já tirado do tapete que ainda está voando para a carteira.
    var walletInFlight = 0
    var freeTexts: [Entity] = []
    var objective: Objective?
    var objectiveTimer: Float = 0

    private init() {
        save = SaveStore.load()
        syncStateFromSave()
    }

    // MARK: - Ciclo de vida

    /// Liga o mundo a uma `ARView` (modo não-AR) e monta a cena na primeira vez.
    func attach(to view: ARView) {
        arView = view
        view.environment.background = .color(UIColor(hex: 0x9EDCF5))
        view.renderOptions.insert(.disableMotionBlur)
        view.renderOptions.insert(.disableDepthOfField)
        view.renderOptions.insert(.disableCameraGrain)
        view.scene.addAnchor(anchor)

        guard !isReady else { return }
        anchor.addChild(root)
        setupCameraAndLight()
        buildWorld()
        snapCamera()
        isReady = true
    }

    /// Apaga o progresso e remonta o mundo do zero.
    func resetGame() {
        isReady = false
        SaveStore.erase()
        save = SaveData()
        save.soundOn = state.soundOn

        root.removeFromParent()
        root = Entity()
        anchor.addChild(root)
        pool = EntityPool()

        player = nil
        sickle = nil
        helpers = []
        slotPiles = [:]
        cashPile = nil
        trayPiles = [:]
        pads = [:]
        obstacles = [:]
        zoneCovers = [:]
        barnModel = nil
        targetArrow = nil
        groundArrow = nil
        crops = []
        cropPositions = []
        cropRipe = []
        growing = []
        walkRects = []
        colliders = []
        queues = [:]
        leaving = []
        freeCustomers = []
        spawnTimers = [:]
        activeParticles = 0
        walletInFlight = 0
        freeTexts = []
        objective = nil
        objectiveTimer = 0
        input = .zero

        syncStateFromSave()
        buildWorld()
        snapCamera()
        isReady = true
        saveNow()
    }

    private func syncStateFromSave() {
        state.money = save.money
        state.soundOn = save.soundOn
        state.showMoveHint = !save.didMove
        state.hasProgress = save.didHarvest
        state.wheat = 0
        state.eggs = 0
        state.pies = 0
        state.labels = []
        audio.enabled = save.soundOn
    }

    private func setupCameraAndLight() {
        cameraEntity.camera.fieldOfViewInDegrees = GameConfig.Camera.fieldOfView
        cameraEntity.camera.near = 2
        cameraEntity.camera.far = 140
        anchor.addChild(cameraEntity)

        let sun = DirectionalLight()
        sun.light.intensity = GameConfig.Visual.sunIntensity
        sun.light.color = UIColor(hex: 0xFFF6E0)
        sun.look(at: Vec3(0, 0, 0), from: Vec3(5, 12, 7), relativeTo: nil)
        anchor.addChild(sun)
    }

    /// Posição ideal da câmera para o ponto focado.
    func cameraPosition(focus: Vec3) -> Vec3 {
        let pitch = GameConfig.Camera.pitchDegrees * .pi / 180
        return focus + Vec3(0, sin(pitch), cos(pitch)) * GameConfig.Camera.distance
    }

    /// Ponto que a câmera enquadra: um pouco à frente (norte) do jogador.
    func cameraFocus() -> Vec3 {
        let base = player?.position ?? vec3(GameConfig.Player.startPosition)
        return Vec3(base.x, 0.6, base.z + GameConfig.Camera.focusOffsetZ)
    }

    /// Coloca a câmera direto no lugar e fixa a orientação (ela nunca gira depois disso).
    private func snapCamera() {
        let focus = cameraFocus()
        cameraEntity.look(at: focus, from: cameraPosition(focus: focus), relativeTo: nil)
    }

    // MARK: - Dinheiro

    func addMoney(_ amount: Int) {
        save.money += amount
        state.money = save.money
    }

    func spend(_ amount: Int) {
        save.money = max(0, save.money - amount)
        state.money = save.money
    }

    /// Preço de venda de uma unidade, já com o bônus de promoção.
    func price(of kind: ItemKind) -> Int {
        Int((Float(GameConfig.Customers.basePrice(kind)) * priceMultiplier).rounded())
    }

    // MARK: - Som

    func toggleSound() {
        state.soundOn.toggle()
        save.soundOn = state.soundOn
        audio.enabled = state.soundOn
        saveNow()
    }

    /// Som + vibração para um evento do jogo.
    func feedback(_ kind: Feedback) {
        switch kind {
        case .harvest:
            audio.play(.harvest, minGap: 0.07)
            haptics.tap()
        case .drop:
            audio.play(.drop, minGap: 0.06)
            haptics.tap()
        case .pickup:
            audio.play(.pop, minGap: 0.06)
            haptics.tap()
        case .coin:
            audio.play(.coin, minGap: 0.07)
            haptics.tap()
        case .pay:
            audio.play(.drop, minGap: 0.08)
            haptics.tap()
        case .chop:
            audio.play(.chop, minGap: 0.1)
            haptics.thump()
        case .build:
            audio.play(.build, minGap: 0.2)
            haptics.success()
        case .deny:
            audio.play(.deny, minGap: 0.5)
            haptics.warning()
        case .sell:
            audio.play(.coin, minGap: 0.1)
            haptics.tap()
        case .produce:
            audio.play(.pop, minGap: 0.25)
        }
    }

    // MARK: - Persistência

    /// Grava o progresso agora (inclui estoque do balcão e das bandejas, a pilha das costas
    /// e o dinheiro no tapete). Itens em voo contam como já entregues.
    func saveNow() {
        guard isReady else { return }
        for (kind, pile) in slotPiles {
            if let component = pile.components[PileComponent.self] {
                save.counterStock[kind.rawValue] = component.count + component.incoming
            }
        }
        for (key, pile) in trayPiles {
            if let component = pile.components[PileComponent.self] {
                save.trayStock[key] = component.count + component.incoming
            }
        }
        if let component = cashPile?.components[PileComponent.self] {
            save.cashOnMat = component.count + component.incoming
        }
        if let carrier = player?.components[CarrierComponent.self] {
            save.carried = carrier.items.map(\.rawValue)
        }
        // As notas que ainda estão no ar já saíram do tapete: entram na carteira do arquivo,
        // senão o dinheiro sumiria se o app fosse fechado neste instante.
        var snapshot = save
        snapshot.money += walletInFlight
        SaveStore.write(snapshot)
        autosaveTimer = 0
    }

    // MARK: - Navegação

    private func isInsideUnlocked(_ p: Vec2) -> Bool {
        for rect in walkRects where rect.contains(p) { return true }
        return false
    }

    /// Verdadeiro se um círculo de raio `margin` em `p` cabe nas zonas liberadas.
    func isWalkable(_ p: Vec2, margin: Float) -> Bool {
        isInsideUnlocked(Vec2(p.x + margin, p.y))
            && isInsideUnlocked(Vec2(p.x - margin, p.y))
            && isInsideUnlocked(Vec2(p.x, p.y + margin))
            && isInsideUnlocked(Vec2(p.x, p.y - margin))
    }

    /// Empurra o ponto para fora das construções.
    func resolveColliders(_ p: Vec2, radius: Float) -> Vec2 {
        var result = p
        for collider in colliders {
            let delta = result - collider.center
            let distance = simd_length(delta)
            let minimum = collider.radius + radius
            if distance < minimum {
                if distance < 0.0001 {
                    result = collider.center + Vec2(0, minimum)
                } else {
                    result = collider.center + delta / distance * minimum
                }
            }
        }
        return result
    }

    /// Verdadeiro se o círculo cabe nas zonas liberadas e não encosta em nenhuma construção.
    func isFree(_ p: Vec2, radius: Float) -> Bool {
        guard isWalkable(p, margin: radius) else { return false }
        for collider in colliders where simd_distance(p, collider.center) < collider.radius + radius - 0.001 {
            return false
        }
        return true
    }

    /// Ponto livre mais próximo de `p`, procurando em anéis cada vez maiores.
    /// Usado como rede de segurança para ninguém ficar preso dentro de uma construção ou fora do mapa.
    func nearestFreeSpot(_ p: Vec2, radius: Float) -> Vec2 {
        if isFree(p, radius: radius) { return p }
        let pushed = resolveColliders(p, radius: radius)
        if isFree(pushed, radius: radius) { return pushed }
        let directions = 16
        for ring in 1...40 {
            let distance = Float(ring) * 0.25
            for step in 0..<directions {
                let angle = Float(step) / Float(directions) * 2 * .pi
                let candidate = p + Vec2(sin(angle), cos(angle)) * distance
                if isFree(candidate, radius: radius) { return candidate }
            }
        }
        return p
    }

    /// Jogador e ajudantes (quem tem pilha nas costas).
    func carriers(playerOnly: Bool) -> [Entity] {
        var list: [Entity] = []
        if let player { list.append(player) }
        if !playerOnly { list.append(contentsOf: helpers) }
        return list
    }

    // MARK: - Itens em voo

    /// Lança um item do pool em arco. Se `target` for nil, `offset` é uma posição do mundo.
    @discardableResult
    func launch(_ kind: ItemKind,
                from start: Vec3,
                to target: Entity?,
                offset: Vec3,
                receiver: Entity? = nil,
                arrival: FlightArrival,
                duration: Float = GameConfig.Flight.duration,
                arc: Float = GameConfig.Flight.arcHeight) -> Entity {
        let item = pool.acquire(kind)
        item.position = start
        root.addChild(item)
        item.components.set(FlightComponent(start: start,
                                            target: target,
                                            targetOffset: offset,
                                            receiver: receiver,
                                            arrival: arrival,
                                            duration: duration,
                                            arc: arc))
        return item
    }

    /// Notas voando do balcão para o tapete depois de uma venda.
    func spawnCash(amount: Int, from start: Vec3) {
        guard let cashPile, amount > 0, let pile = cashPile.components[PileComponent.self] else { return }
        let notes = min(GameConfig.Cash.notesPerSale, amount)
        var remaining = amount
        for i in 0..<notes {
            let share = i == notes - 1 ? remaining : amount / notes
            remaining -= share
            if share <= 0 { continue }
            launch(.cash,
                   from: start,
                   to: cashPile,
                   offset: pile.landingSlot,
                   receiver: cashPile,
                   arrival: .pile(share),
                   duration: 0.42 + Float(i) * 0.07,
                   arc: 1.7)
            cashPile.modify(PileComponent.self) { $0.incoming += share }
        }
    }

    // MARK: - Efeitos

    /// Solta partículas (palha ou lascas) com gravidade.
    func spawnParticles(_ kind: ItemKind, at position: Vec3, count: Int, spread: Float) {
        for _ in 0..<count {
            guard activeParticles < GameConfig.Visual.maxParticles else { return }
            let particle = pool.acquire(kind)
            particle.position = position
            particle.components.set(ParticleComponent(
                velocity: Vec3(Float.random(in: -spread...spread),
                               Float.random(in: 2.5...4.5),
                               Float.random(in: -spread...spread)),
                spin: Vec3(Float.random(in: -9...9), Float.random(in: -9...9), Float.random(in: -9...9)),
                life: Float.random(in: 0.45...0.75)))
            root.addChild(particle)
            activeParticles += 1
        }
    }

    func releaseParticle(_ particle: Entity) {
        activeParticles = max(0, activeParticles - 1)
        pool.release(particle)
    }

    /// Texto que sobe e some na posição do mundo.
    func floatText(_ text: String, style: LabelStyle, at position: Vec3, life: Float = 1.1) {
        let entity = freeTexts.popLast() ?? Entity()
        entity.position = position
        entity.components.set(LabelComponent(text: text, style: style, offset: Vec3(0, 0, 0)))
        entity.components.set(FloatingTextComponent(life: life, maxLife: life, rise: 1.3))
        root.addChild(entity)
    }

    func recycleText(_ entity: Entity) {
        entity.removeFromParent()
        entity.components.remove(LabelComponent.self)
        entity.components.remove(FloatingTextComponent.self)
        freeTexts.append(entity)
    }
}

extension Entity {
    /// Lê, altera e regrava um componente (componentes são structs).
    func modify<C: Component>(_ type: C.Type, _ body: (inout C) -> Void) {
        guard var value = components[type] else { return }
        body(&value)
        components.set(value)
    }
}
