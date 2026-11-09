import Foundation
import RealityKit
import simd

/// Regras de progressão: pads, upgrades, obstáculos, clientes e objetivo atual.
extension GameWorld {

    // MARK: - Níveis e upgrades

    /// Nível já comprado de um pad.
    func level(_ kind: PadKind) -> Int {
        save.padLevels[kind.rawValue] ?? 0
    }

    /// Recalcula tudo que depende dos níveis comprados.
    func applyUpgrades() {
        let sickleLevel = level(.sickle)
        let trainingLevel = level(.training)

        playerSpeed = GameConfig.Player.baseSpeed + Float(level(.boots)) * GameConfig.Player.speedPerBootsLevel
        helperSpeed = GameConfig.Helpers.baseSpeed + Float(trainingLevel) * GameConfig.Helpers.speedPerTrainingLevel
        regrowTime = GameConfig.Crops.regrowTime * pow(GameConfig.Crops.regrowFactorPerWateringLevel, Float(level(.wateringCan)))
        productionSpeed = 1 + Float(level(.oven)) * GameConfig.Upgrades.ovenSpeedPerLevel
        priceMultiplier = 1 + Float(level(.promo)) * GameConfig.Customers.promoBonusPerLevel
        obstacleDPS = GameConfig.Obstacles.baseDPS + Float(sickleLevel) * GameConfig.Obstacles.dpsPerSickleLevel

        let capacity = GameConfig.Player.baseCapacity
            + level(.barn) * GameConfig.Barn.capacityOnBuild
            + level(.barnUpgrade) * GameConfig.Barn.capacityPerUpgrade
        let radius = GameConfig.Sickle.baseRadius + Float(sickleLevel) * GameConfig.Sickle.radiusPerLevel
        let interval = GameConfig.Sickle.baseInterval * pow(GameConfig.Sickle.intervalFactorPerLevel, Float(sickleLevel))

        player?.modify(CarrierComponent.self) { $0.capacity = capacity }
        player?.modify(HarvesterComponent.self) {
            $0.radius = radius
            $0.interval = interval
        }
        // A foice cresce a cada nível, para o upgrade ser visível.
        sickle?.scale = Vec3(repeating: 1 + Float(sickleLevel) * 0.16)

        let helperCapacity = GameConfig.Helpers.baseCapacity + trainingLevel * GameConfig.Helpers.capacityPerTrainingLevel
        for helper in helpers {
            helper.modify(CarrierComponent.self) { $0.capacity = helperCapacity }
        }
    }

    // MARK: - Pads

    private func isSatisfied(_ requirement: PadRequirement) -> Bool {
        switch requirement {
        case .zone(let id): return save.unlockedZones.contains(id)
        case .pad(let kind, let minimum): return level(kind) >= minimum
        }
    }

    /// Cria os pads que ficaram disponíveis e remove os que não fazem mais sentido.
    func refreshPads(animated: Bool) {
        for def in WorldLayout.pads {
            let available = level(def.kind) < def.prices.count && def.requires.allSatisfy { isSatisfied($0) }
            if available {
                if pads[def.kind] == nil { spawnPad(def, animated: animated) }
            } else if let pad = pads[def.kind] {
                removePad(pad, kind: def.kind)
            }
        }
    }

    private func spawnPad(_ def: PadDef, animated: Bool) {
        let made = PropFactory.makePad()
        let pad = made.root
        pad.position = vec3(def.position)
        pad.components.set(PadComponent(kind: def.kind,
                                        prices: def.prices,
                                        level: level(def.kind),
                                        paid: save.padPaid[def.kind.rawValue] ?? 0,
                                        progressFill: made.fill))
        pad.components.set(LabelComponent(text: "", style: .pad, offset: Vec3(0, 0.7, 0), icon: def.kind))
        if animated {
            pad.components.set(PopComponent(style: .grow, duration: 0.4, base: Vec3(1, 1, 1)))
        }
        root.addChild(pad)
        pads[def.kind] = pad
    }

    private func removePad(_ pad: Entity, kind: PadKind) {
        pads[kind] = nil
        pad.components.remove(PadComponent.self)
        pad.components.remove(LabelComponent.self)
        pad.components.set(PopComponent(style: .shrink, duration: 0.3, base: pad.scale, finish: .remove))
    }

    /// Chamado pelo `PadSystem` quando o nível atual do pad foi pago por inteiro.
    func completePad(_ pad: Entity) {
        guard var component = pad.components[PadComponent.self] else { return }
        component.level += 1
        component.paid = 0
        component.payAccumulator = 0
        component.dwell = 0
        component.progressFill.scale = Vec3(0.02, 1, 0.02)
        pad.components.set(component)

        let kind = component.kind
        save.padLevels[kind.rawValue] = component.level
        save.padPaid[kind.rawValue] = 0

        switch kind {
        case .hireHelper:
            spawnHelper(index: component.level - 1, animated: true)
        case .coop:
            buildCoop(animated: true)
        case .bakery:
            buildBakery(animated: true)
        case .barn:
            buildBarn(animated: true)
        case .barnUpgrade:
            barnModel?.components.set(PopComponent(style: .bounce, duration: 0.4, base: Vec3(1, 1, 1)))
        default:
            break
        }

        applyUpgrades()
        feedback(.build)
        floatText(kind.doneText, style: .gain, at: pad.position + Vec3(0, 1.8, 0), life: 1.6)
        spawnParticles(.straw, at: pad.position + Vec3(0, 0.5, 0), count: 10, spread: 3)

        if component.level >= component.prices.count {
            removePad(pad, kind: kind)
        }
        refreshPads(animated: true)
        saveNow()
    }

    // MARK: - Obstáculos

    /// Chamado pelo `ObstacleSystem` quando a vida chega a zero.
    func destroyObstacle(_ obstacle: Entity) {
        guard let component = obstacle.components[ObstacleComponent.self] else { return }
        obstacles[component.id] = nil
        save.destroyedObstacles.insert(component.id)
        save.obstacleHealth[component.id] = nil

        obstacle.components.remove(ObstacleComponent.self)
        obstacle.components.remove(LabelComponent.self)
        obstacle.components.set(PopComponent(style: .shrink, duration: 0.35, base: obstacle.scale, finish: .remove))
        spawnParticles(.chip, at: obstacle.position + Vec3(0, 0.7, 0), count: 16, spread: 3.5)
        feedback(.build)
        floatText("ÁREA LIBERADA!", style: .gain, at: obstacle.position + Vec3(0, 2, 0), life: 1.6)

        if let zone = WorldLayout.zones.first(where: { $0.id == component.unlocksZone }),
           !save.unlockedZones.contains(zone.id) {
            save.unlockedZones.insert(zone.id)
            openZone(zone, animated: true)
        }
        refreshPads(animated: true)
        objectiveTimer = 0
        saveNow()
    }

    // MARK: - Plantação

    /// Corta o pé de trigo de índice `index` e inicia a rebrota.
    func harvestCrop(_ index: Int) {
        cropRipe[index] = false
        let crop = crops[index]
        let duration = regrowTime
        crop.modify(CropComponent.self) {
            $0.isRipe = false
            $0.timer = duration
            $0.duration = duration
        }
        crop.components.remove(PopComponent.self)
        crop.scale = CropVisual.scale(progress: 0)
        growing.append(index)
        spawnParticles(.straw, at: vec3(cropPositions[index], 0.4), count: 2, spread: 2.2)
    }

    /// Trigo maduro mais próximo (com um pouco de sorteio para os ajudantes não andarem em fila).
    func nearestRipeCrop(to position: Vec2) -> Int? {
        var best: Int?
        var bestScore = Float.greatestFiniteMagnitude
        for index in 0..<cropPositions.count where cropRipe[index] {
            let delta = cropPositions[index] - position
            let score = delta.x * delta.x + delta.y * delta.y + Float.random(in: 0...6)
            if score < bestScore {
                bestScore = score
                best = index
            }
        }
        return best
    }

    // MARK: - Clientes

    /// A fila de um produto só abre quando ele pode ser produzido.
    func isQueueOpen(_ kind: ItemKind) -> Bool {
        switch kind {
        case .wheat: return true
        case .egg: return level(.coop) > 0
        case .pie: return level(.bakery) > 0
        default: return false
        }
    }

    /// Coloca um cliente novo (ou reciclado) no fim da fila do produto.
    func spawnCustomer(_ kind: ItemKind) {
        let customer: Entity
        if let reused = freeCustomers.popLast() {
            customer = reused
        } else {
            customer = CharacterFactory.make(style: .customer(using: &customerRandom), constrained: false)
        }
        let spawn = WorldLayout.customerSpawn(kind)
        customer.position = vec3(spawn + Vec2(Float.random(in: -0.4...0.4), Float.random(in: -0.4...0.4)))

        let wanted = Int.random(in: GameConfig.Customers.wantedRange(kind))
        let facing = WorldLayout.queueFacing(kind)
        customer.components.set(CustomerComponent(product: kind, wanted: wanted))
        customer.components.set(LabelComponent(text: "\(kind.emoji) \(wanted)", style: .bubble, offset: Vec3(0, 1.75, 0)))
        customer.modify(MotionComponent.self) {
            $0.velocity = .zero
            $0.heading = facing
            $0.faceHeading = nil
        }
        root.addChild(customer)
        queues[kind, default: []].append(customer)
    }

    /// Tira o cliente atendido da fila e manda embora pelo caminho de saída.
    func sendCustomerAway(_ customer: Entity, kind: ItemKind) {
        if let index = queues[kind]?.firstIndex(where: { $0 === customer }) {
            queues[kind]?.remove(at: index)
        }
        customer.components.remove(LabelComponent.self)
        let path = WorldLayout.customerExit(kind)
        customer.modify(CustomerComponent.self) {
            $0.isLeaving = true
            $0.exitPath = path
            $0.exitIndex = 0
        }
        customer.modify(MotionComponent.self) { $0.faceHeading = nil }
        leaving.append(customer)
    }

    /// Devolve o cliente ao pool depois que ele saiu de cena.
    func releaseCustomer(_ customer: Entity) {
        leaving.removeAll { $0 === customer }
        customer.removeFromParent()
        customer.components.remove(CustomerComponent.self)
        customer.modify(MotionComponent.self) { $0.velocity = .zero }
        freeCustomers.append(customer)
    }

    // MARK: - Objetivo

    /// Decide para onde a seta de objetivo aponta agora (nil = nada a indicar).
    func computeObjective() -> Objective? {
        let carrier = player?.components[CarrierComponent.self]
        let carriesWheat = carrier?.items.contains(.wheat) ?? false
        let carriesAnything = !(carrier?.items.isEmpty ?? true)
        let fieldCenter = WorldLayout.zones[0].fields[0].center
        let field = Objective(position: vec3(fieldCenter), height: 2.0)
        let wheatSlot = Objective(position: vec3(WorldLayout.slotPosition(.wheat) + Vec2(0, -0.9)), height: 2.4)
        let cashOnMat = cashPile?.components[PileComponent.self]?.count ?? 0
        let mat = Objective(position: vec3(WorldLayout.cashMat), height: 1.8)

        // Tutorial: colher → entregar → recolher o dinheiro.
        if !save.didHarvest { return field }
        if !save.didSell {
            return carriesWheat ? wheatSlot : field
        }
        if !save.didCollectCash {
            if cashOnMat > 0 { return mat }
            return carriesWheat ? wheatSlot : field
        }

        // Primeiro obstáculo.
        if let first = WorldLayout.obstacles.first, let entity = obstacles[first.id] {
            return Objective(position: entity.position, height: 3.0)
        }

        // Próximo pad disponível, na ordem de progressão.
        for def in WorldLayout.pads {
            if let pad = pads[def.kind], let component = pad.components[PadComponent.self] {
                let missing = component.currentPrice - component.paid - save.money
                if missing > 0 && cashOnMat > 0 { return mat }
                // Sem nenhum dinheiro, o pad só responderia "SEM DINHEIRO":
                // a seta leva a ganhar dinheiro primeiro (vender o que carrega ou colher).
                if missing > 0 && save.money == 0 {
                    if carriesWheat { return wheatSlot }
                    if !carriesAnything { return field }
                }
                return Objective(position: pad.position, height: 2.6)
            }
        }

        // Próximo obstáculo alcançável.
        for def in WorldLayout.obstacles where save.unlockedZones.contains(def.reachableFromZone) {
            if let entity = obstacles[def.id] {
                return Objective(position: entity.position, height: def.kind == .deadTree ? 3.9 : 3.0)
            }
        }
        return nil
    }
}
