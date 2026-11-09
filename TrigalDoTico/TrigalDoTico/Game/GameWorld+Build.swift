import Foundation
import RealityKit
import simd

/// Montagem da cena: chão, balcão, zonas, obstáculos, jogador e construções já compradas.
extension GameWorld {

    func buildWorld() {
        root.addChild(PropFactory.makeGround())
        root.addChild(PropFactory.makeScenery())
        root.addChild(PropFactory.makeCounter())
        buildCashMat()
        buildCounterSlots()

        for zone in WorldLayout.zones {
            if save.unlockedZones.contains(zone.id) {
                openZone(zone, animated: false)
            } else {
                let cover = PropFactory.makeZoneCover(zone)
                root.addChild(cover)
                zoneCovers[zone.id] = cover
            }
        }

        for def in WorldLayout.obstacles where !save.destroyedObstacles.contains(def.id) {
            spawnObstacle(def)
        }

        spawnPlayer()

        if level(.coop) > 0 { buildCoop(animated: false) }
        if level(.bakery) > 0 { buildBakery(animated: false) }
        if level(.barn) > 0 { buildBarn(animated: false) }
        for index in 0..<level(.hireHelper) {
            spawnHelper(index: index, animated: false)
        }

        buildIndicators()
        applyUpgrades()
        refreshPads(animated: false)

        // Aquece o pool para não criar entidades no meio da ação.
        pool.prewarm(.wheat, count: 60)
        pool.prewarm(.cash, count: 40)
        pool.prewarm(.straw, count: 30)
        pool.prewarm(.chip, count: 20)
    }

    // MARK: - Balcão e dinheiro

    private func buildCashMat() {
        let position = WorldLayout.cashMat
        let mat = PropFactory.makeCashMat()
        mat.position = vec3(position)
        root.addChild(mat)

        let pile = Entity()
        pile.position = vec3(position, 0.07)
        pile.components.set(PileComponent(kind: .cash,
                                          count: save.cashOnMat,
                                          capacity: Int.max / 4,
                                          columns: 3,
                                          rows: 3,
                                          maxVisible: GameConfig.Cash.maxNotesVisible,
                                          unitsPerVisual: GameConfig.Cash.unitsPerNote))
        pile.components.set(StationComponent(mode: .cashCollect,
                                             radius: GameConfig.Cash.matRadius,
                                             interval: GameConfig.Cash.collectInterval,
                                             playerOnly: true))
        root.addChild(pile)
        cashPile = pile
    }

    private func buildCounterSlots() {
        for kind in ItemKind.products {
            let slot = WorldLayout.slotPosition(kind)
            let pile = Entity()
            pile.position = vec3(slot, WorldLayout.counterTop)
            pile.components.set(PileComponent(kind: kind,
                                              count: save.counterStock[kind.rawValue] ?? 0,
                                              capacity: GameConfig.Counter.slotCapacity,
                                              maxVisible: GameConfig.Counter.maxVisible))
            pile.components.set(StationComponent(mode: .deposit,
                                                 radius: GameConfig.Counter.slotRadius,
                                                 interval: GameConfig.Counter.transferInterval,
                                                 playerOnly: false))
            // Etiqueta do produto no lado do jogador (o braço curto do balcão fica a leste).
            let tagOffset = kind == .pie ? Vec3(-0.85, -0.3, 0) : Vec3(0, -0.3, -0.85)
            pile.components.set(LabelComponent(text: kind.emoji, style: .tag, offset: tagOffset))
            root.addChild(pile)
            slotPiles[kind] = pile
        }
    }

    /// Bandeja + monte com estação de troca, usado pelas construções.
    /// `key` identifica a bandeja no save (o estoque dela sobrevive entre sessões).
    private func makeStation(key: String,
                             kind: ItemKind,
                             at position: Vec2,
                             mode: StationComponent.Mode,
                             capacity: Int,
                             trayColor: UInt32,
                             showTag: Bool,
                             animated: Bool) -> Entity {
        let tray = PropFactory.makeTray(color: trayColor)
        tray.position = vec3(position)
        root.addChild(tray)

        let pile = Entity()
        pile.position = vec3(position, 0.13)
        let stock = min(capacity, max(0, save.trayStock[key] ?? 0))
        pile.components.set(PileComponent(kind: kind, count: stock, capacity: capacity, maxVisible: 12))
        pile.components.set(StationComponent(mode: mode,
                                             radius: 1.25,
                                             interval: GameConfig.Counter.transferInterval,
                                             playerOnly: mode != .deposit))
        if showTag {
            pile.components.set(LabelComponent(text: kind.emoji, style: .tag, offset: Vec3(0, 0, 0.62)))
        }
        root.addChild(pile)
        trayPiles[key] = pile

        if animated {
            tray.components.set(PopComponent(style: .grow, duration: 0.45, base: Vec3(1, 1, 1)))
        }
        return pile
    }

    // MARK: - Zonas e plantação

    /// Libera uma zona: passa a ser caminhável, some o mato e nasce o campo.
    func openZone(_ zone: ZoneDef, animated: Bool) {
        walkRects.append(zone.rect)

        if let cover = zoneCovers.removeValue(forKey: zone.id) {
            cover.components.set(PopComponent(style: .shrink, duration: 0.5, base: cover.scale, finish: .remove))
        }

        let spacing = GameConfig.Crops.spacing
        for (fieldIndex, field) in zone.fields.enumerated() {
            root.addChild(PropFactory.makeSoil(field, key: "soil.\(zone.id).\(fieldIndex)"))
            var rng = SeededRandom(seed: UInt64(zone.id * 97 + fieldIndex * 13 + 1))
            var z = field.minZ + spacing / 2
            while z < field.maxZ {
                var x = field.minX + spacing / 2
                while x < field.maxX {
                    let jitter = Vec2(Float.random(in: -0.07...0.07, using: &rng),
                                      Float.random(in: -0.07...0.07, using: &rng))
                    addCrop(at: Vec2(x, z) + jitter, yaw: Float.random(in: 0...(2 * .pi), using: &rng), animated: animated)
                    x += spacing
                }
                z += spacing
            }
        }
    }

    private func addCrop(at position: Vec2, yaw: Float, animated: Bool) {
        let crop = PropFactory.makeCrop()
        crop.position = vec3(position)
        crop.orientation = simd_quatf(angle: yaw, axis: Vec3(0, 1, 0))
        let index = crops.count
        if animated {
            // Nasce aos poucos, com atraso sorteado, usando o mesmo sistema da rebrota.
            let delay = Float.random(in: 0.4...1.6)
            crop.components.set(CropComponent(index: index, isRipe: false, timer: delay, duration: delay))
            crop.scale = CropVisual.scale(progress: 0)
            growing.append(index)
        } else {
            crop.components.set(CropComponent(index: index))
        }
        root.addChild(crop)
        crops.append(crop)
        cropPositions.append(position)
        cropRipe.append(!animated)
    }

    // MARK: - Obstáculos

    private func spawnObstacle(_ def: ObstacleDef) {
        let obstacle = PropFactory.makeObstacle(def.kind)
        obstacle.position = vec3(def.position)
        obstacle.addChild(ModelFactory.shadow(radius: 1.15))
        let health = save.obstacleHealth[def.id] ?? def.health
        obstacle.components.set(ObstacleComponent(id: def.id, health: health, unlocksZone: def.unlocksZone))
        let labelHeight: Float = def.kind == .deadTree ? 2.7 : 1.7
        obstacle.components.set(LabelComponent(text: "\(Int(health.rounded(.up)))", style: .health, offset: Vec3(0, labelHeight, 0)))
        root.addChild(obstacle)
        obstacles[def.id] = obstacle
    }

    // MARK: - Personagens

    private func spawnPlayer() {
        let entity = CharacterFactory.make(style: .player, constrained: true)
        entity.position = vec3(GameConfig.Player.startPosition)

        let stackAnchor = CharacterFactory.makeStackAnchor()
        entity.addChild(stackAnchor)

        if let rig = entity.components[CharacterRigComponent.self] {
            let tool = CharacterFactory.makeSickle()
            rig.armRight.addChild(tool)
            sickle = tool
        }

        // Devolve o que o jogador carregava quando o jogo foi salvo (só produtos conhecidos).
        let carried = save.carried.compactMap { ItemKind(rawValue: $0) }.filter { ItemKind.products.contains($0) }

        entity.components.set(PlayerComponent())
        entity.components.set(CarrierComponent(items: carried,
                                               capacity: GameConfig.Player.baseCapacity,
                                               anchor: stackAnchor,
                                               showsMaxLabel: true))
        entity.components.set(HarvesterComponent(radius: GameConfig.Sickle.baseRadius, interval: GameConfig.Sickle.baseInterval, isPlayer: true))
        entity.components.set(LabelComponent(text: "MAX", style: .max, offset: Vec3(0, 2, 0), visible: false))
        root.addChild(entity)
        player = entity
    }

    /// Cria um ajudante que colhe sozinho e leva o trigo ao balcão.
    func spawnHelper(index: Int, animated: Bool) {
        let entity = CharacterFactory.make(style: .helper, constrained: true)
        let padPosition = WorldLayout.pads.first(where: { $0.kind == .hireHelper })?.position ?? Vec2(-5.7, 2.9)
        entity.position = vec3(padPosition + Vec2(1.3 + Float(index) * 0.5, -0.9))

        let stackAnchor = CharacterFactory.makeStackAnchor()
        entity.addChild(stackAnchor)

        entity.components.set(HelperComponent(index: index))
        entity.components.set(CarrierComponent(capacity: GameConfig.Helpers.baseCapacity, anchor: stackAnchor))
        entity.components.set(HarvesterComponent(radius: GameConfig.Helpers.harvestRadius, interval: GameConfig.Helpers.harvestInterval, isPlayer: false))
        if animated {
            entity.components.set(PopComponent(style: .grow, duration: 0.45, base: entity.scale))
        }
        root.addChild(entity)
        helpers.append(entity)
    }

    // MARK: - Construções

    /// Galinheiro: consome trigo e põe ovos na bandeja.
    func buildCoop(animated: Bool) {
        let site = WorldLayout.coopSite
        let coop = Entity()
        coop.position = vec3(site)
        root.addChild(coop)

        let model = PropFactory.makeCoop()
        model.addChild(ModelFactory.shadow(radius: 1.8))
        coop.addChild(model)

        for i in 0..<3 {
            let chicken = PropFactory.makeChicken()
            chicken.addChild(ModelFactory.shadow(radius: 0.22))
            chicken.components.set(ChickenComponent(home: Vec3(-0.6 + Float(i) * 0.6, 0, 1.25), phase: Float(i) * 2.1))
            coop.addChild(chicken)
        }

        let input = makeStation(key: "coop.wheat", kind: .wheat, at: site + Vec2(-1.05, 2.25), mode: .deposit,
                                capacity: GameConfig.Coop.inputCapacity, trayColor: Palette.wood, showTag: true, animated: animated)
        let output = makeStation(key: "coop.egg", kind: .egg, at: site + Vec2(1.05, 2.25), mode: .pickup,
                                 capacity: GameConfig.Coop.outputCapacity, trayColor: Palette.woodLight, showTag: false, animated: animated)

        coop.components.set(ProducerComponent(inputs: [input],
                                              costs: [GameConfig.Coop.wheatPerEgg],
                                              output: output,
                                              interval: GameConfig.Coop.interval,
                                              model: model))
        colliders.append(Collider(center: site, radius: 1.5))
        if animated {
            model.components.set(PopComponent(style: .grow, duration: 0.55, base: Vec3(1, 1, 1)))
        }
    }

    /// Padaria: consome trigo e ovos e assa tortas.
    func buildBakery(animated: Bool) {
        let site = WorldLayout.bakerySite
        let bakery = Entity()
        bakery.position = vec3(site)
        root.addChild(bakery)

        let model = PropFactory.makeBakery()
        model.addChild(ModelFactory.shadow(radius: 2.0))
        bakery.addChild(model)

        let wheatIn = makeStation(key: "bakery.wheat", kind: .wheat, at: site + Vec2(-1.3, 2.0), mode: .deposit,
                                  capacity: GameConfig.Bakery.inputCapacity, trayColor: Palette.wood, showTag: true, animated: animated)
        let eggIn = makeStation(key: "bakery.egg", kind: .egg, at: site + Vec2(0, 2.0), mode: .deposit,
                                capacity: GameConfig.Bakery.inputCapacity, trayColor: Palette.wood, showTag: true, animated: animated)
        let pieOut = makeStation(key: "bakery.pie", kind: .pie, at: site + Vec2(1.3, 2.0), mode: .pickup,
                                 capacity: GameConfig.Bakery.outputCapacity, trayColor: Palette.woodLight, showTag: false, animated: animated)

        bakery.components.set(ProducerComponent(inputs: [wheatIn, eggIn],
                                                costs: [GameConfig.Bakery.wheatPerPie, GameConfig.Bakery.eggsPerPie],
                                                output: pieOut,
                                                interval: GameConfig.Bakery.interval,
                                                model: model))
        colliders.append(Collider(center: site, radius: 1.6))
        if animated {
            model.components.set(PopComponent(style: .grow, duration: 0.55, base: Vec3(1, 1, 1)))
        }
    }

    /// Celeiro: aumenta a capacidade da pilha (o efeito é aplicado em `applyUpgrades`).
    func buildBarn(animated: Bool) {
        let site = WorldLayout.barnSite
        let model = PropFactory.makeBarn()
        model.addChild(ModelFactory.shadow(radius: 2.1))
        model.position = vec3(site)
        root.addChild(model)
        barnModel = model
        colliders.append(Collider(center: site, radius: 1.75))
        if animated {
            model.components.set(PopComponent(style: .grow, duration: 0.55, base: Vec3(1, 1, 1)))
        }
    }

    // MARK: - Indicadores

    private func buildIndicators() {
        let target = PropFactory.makeTargetArrow()
        target.isEnabled = false
        root.addChild(target)
        targetArrow = target

        let ground = PropFactory.makeGroundArrow()
        ground.isEnabled = false
        root.addChild(ground)
        groundArrow = ground
    }
}
