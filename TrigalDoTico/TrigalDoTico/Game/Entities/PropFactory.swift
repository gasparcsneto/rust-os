import RealityKit
import simd

/// Constrói todos os objetos do cenário com primitivas low-poly e cores chapadas.
@MainActor
enum PropFactory {

    private static func yaw(_ angle: Float) -> simd_quatf {
        simd_quatf(angle: angle, axis: Vec3(0, 1, 0))
    }

    private static func roll(_ angle: Float) -> simd_quatf {
        simd_quatf(angle: angle, axis: Vec3(0, 0, 1))
    }

    private static func pitch(_ angle: Float) -> simd_quatf {
        simd_quatf(angle: angle, axis: Vec3(1, 0, 0))
    }

    // MARK: - Itens (pool)

    /// Item empilhável, nota de dinheiro ou partícula. A origem fica na base do modelo.
    static func makeItem(_ kind: ItemKind) -> ModelEntity {
        switch kind {
        case .wheat:
            return ModelFactory.model("item.wheat", colors: [Palette.wheat, Palette.wheatBand, Palette.wheatLight]) { b in
                b.box(center: Vec3(0, 0.08, 0), size: Vec3(0.42, 0.15, 0.26), material: 0)
                b.box(center: Vec3(0, 0.08, 0), size: Vec3(0.09, 0.165, 0.275), material: 1)
                b.box(center: Vec3(-0.215, 0.08, 0), size: Vec3(0.05, 0.12, 0.22), material: 2)
                b.box(center: Vec3(0.215, 0.08, 0), size: Vec3(0.05, 0.12, 0.22), material: 2)
            }
        case .egg:
            return ModelFactory.model("item.egg", colors: [Palette.eggCup, Palette.eggShell]) { b in
                b.box(center: Vec3(0, 0.03, 0), size: Vec3(0.3, 0.06, 0.3), material: 0)
                b.ellipsoid(center: Vec3(0, 0.1, 0), radii: Vec3(0.105, 0.085, 0.105), material: 1)
            }
        case .pie:
            return ModelFactory.model("item.pie", colors: [Palette.pieCrust, Palette.pieFilling]) { b in
                b.prism(base: Vec3(0, 0, 0), height: 0.08, bottomRadius: 0.18, topRadius: 0.22, sides: 10, material: 0)
                b.prism(base: Vec3(0, 0.08, 0), height: 0.045, bottomRadius: 0.18, topRadius: 0.1, sides: 10, material: 1)
            }
        case .cash:
            return ModelFactory.model("item.cash", colors: [Palette.cash, Palette.cashLight]) { b in
                b.box(center: Vec3(0, 0.02, 0), size: Vec3(0.36, 0.04, 0.2), material: 0)
                b.box(center: Vec3(0, 0.021, 0), size: Vec3(0.1, 0.044, 0.205), material: 1)
            }
        case .straw:
            return ModelFactory.model("item.straw", colors: [Palette.wheatLight]) { b in
                b.box(center: Vec3(0, 0, 0), size: Vec3(0.13, 0.03, 0.04), material: 0)
            }
        case .chip:
            return ModelFactory.model("item.chip", colors: [Palette.woodLight]) { b in
                b.box(center: Vec3(0, 0, 0), size: Vec3(0.11, 0.045, 0.07), material: 0)
            }
        }
    }

    // MARK: - Plantação

    /// Pé de trigo: três hastes inclinadas com espigas.
    static func makeCrop() -> ModelEntity {
        ModelFactory.model("crop.wheat", colors: [Palette.straw, Palette.wheat]) { b in
            let stalks: [(Vec2, Float, Float)] = [
                (Vec2(-0.12, -0.04), 0.14, 0.52),
                (Vec2(0.1, 0.07), -0.12, 0.6),
                (Vec2(0.0, -0.12), 0.05, 0.46),
            ]
            for (offset, lean, height) in stalks {
                let tilt = simd_quatf(angle: lean, axis: Vec3(0, 0, 1))
                let base = Vec3(offset.x, 0, offset.y)
                b.prism(base: base, height: height, bottomRadius: 0.03, topRadius: 0.02, sides: 4, rotation: tilt, material: 0)
                let tip = base + tilt.act(Vec3(0, height + 0.08, 0))
                b.ellipsoid(center: tip, radii: Vec3(0.065, 0.15, 0.065), segments: 5, rings: 4, material: 1)
            }
        }
    }

    /// Terra arada sob um campo.
    static func makeSoil(_ field: Rect2, key: String) -> ModelEntity {
        ModelFactory.model(key, colors: [Palette.soil]) { b in
            let padded = Vec2(field.size.x + 0.5, field.size.y + 0.5)
            b.flatRect(center: field.center, size: padded, y: 0.04, material: 0)
        }
    }

    // MARK: - Chão e cenário

    /// Gramado e calçadas dos clientes.
    static func makeGround() -> ModelEntity {
        ModelFactory.model("ground", colors: [Palette.grass, Palette.path]) { b in
            b.flatRect(center: Vec2(-5, -6), size: Vec2(140, 140), y: 0, material: 0)
            b.flatRect(center: Vec2(3, 13.2), size: Vec2(12, 15.2), y: 0.02, material: 1)
            b.flatRect(center: Vec2(15.3, 2.5), size: Vec2(17.4, 6.2), y: 0.02, material: 1)
        }
    }

    /// Árvores decorativas fora da área jogável.
    static func makeScenery() -> ModelEntity {
        ModelFactory.model("scenery", colors: [Palette.woodDark, Palette.grassDark, Palette.bush]) { b in
            var rng = SeededRandom(seed: 77)
            var spots: [Vec2] = []
            for i in 0..<12 { spots.append(Vec2(-17.2 - Float.random(in: 0...2.5, using: &rng), -19 + Float(i) * 2.2)) }
            for i in 0..<11 { spots.append(Vec2(-15 + Float(i) * 2.3, -20 - Float.random(in: 0...2.5, using: &rng))) }
            for i in 0..<8 { spots.append(Vec2(7.4 + Float.random(in: 0...2.5, using: &rng), -19 + Float(i) * 2.2)) }
            for i in 0..<5 { spots.append(Vec2(-15 + Float(i) * 2.4, 6.6 + Float.random(in: 0...2, using: &rng))) }
            for spot in spots {
                let size = Float.random(in: 0.8...1.25, using: &rng)
                b.prism(base: vec3(spot), height: 1.0 * size, bottomRadius: 0.22 * size, topRadius: 0.16 * size, sides: 6, material: 0)
                b.ellipsoid(center: vec3(spot, 1.7 * size), radii: Vec3(0.95, 1.0, 0.95) * size,
                            segments: 7, rings: 4, material: Bool.random(using: &rng) ? 1 : 2)
            }
        }
    }

    /// Cobertura de uma zona trancada: grama escura, arbustos e pedras.
    /// A malha é centrada na origem para encolher em direção ao centro ao ser liberada.
    static func makeZoneCover(_ zone: ZoneDef) -> ModelEntity {
        let cover = ModelFactory.model("zone.cover.\(zone.id)", colors: [Palette.grassDark, Palette.bush, Palette.stone]) { b in
            let size = zone.rect.size
            b.flatRect(center: Vec2(0, 0), size: size, y: 0.02, material: 0)
            var rng = SeededRandom(seed: UInt64(zone.id) &* 31 &+ 5)
            let obstacleSpots = WorldLayout.obstacles.map { $0.position - zone.rect.center }
            var placed = 0
            var attempts = 0
            while placed < 26 && attempts < 200 {
                attempts += 1
                let p = Vec2(Float.random(in: -size.x / 2 + 0.9...size.x / 2 - 0.9, using: &rng),
                             Float.random(in: -size.y / 2 + 0.9...size.y / 2 - 0.9, using: &rng))
                if obstacleSpots.contains(where: { simd_distance($0, p) < 2.2 }) { continue }
                let scale = Float.random(in: 0.7...1.3, using: &rng)
                if placed % 5 == 4 {
                    b.ellipsoid(center: vec3(p, 0.2 * scale), radii: Vec3(0.5, 0.32, 0.42) * scale, segments: 6, rings: 4, material: 2)
                } else {
                    b.ellipsoid(center: vec3(p, 0.3 * scale), radii: Vec3(0.6, 0.45, 0.55) * scale, segments: 6, rings: 4, material: 1)
                }
                placed += 1
            }
        }
        cover.position = vec3(zone.rect.center)
        return cover
    }

    // MARK: - Balcão e dinheiro

    /// Balcão azul em L, já em coordenadas do mundo.
    static func makeCounter() -> ModelEntity {
        ModelFactory.model("counter", colors: [Palette.counter, Palette.counterBelt, Palette.counterPlate]) { b in
            let top = WorldLayout.counterTop
            // Braço comprido (trigo e ovos) e braço curto (tortas).
            b.box(center: Vec3(2.75, (top - 0.05) / 2, 5.0), size: Vec3(7.5, top - 0.05, 1.0), material: 0)
            b.box(center: Vec3(6.0, (top - 0.05) / 2, 2.25), size: Vec3(1.0, top - 0.05, 4.5), material: 0)
            // Esteira.
            b.box(center: Vec3(2.75, top - 0.035, 5.0), size: Vec3(7.3, 0.03, 0.72), material: 1)
            b.box(center: Vec3(6.0, top - 0.035, 2.4), size: Vec3(0.72, 0.03, 4.5), material: 1)
            // Placas dos pontos de entrega.
            for kind in ItemKind.products {
                let slot = WorldLayout.slotPosition(kind)
                b.box(center: Vec3(slot.x, top - 0.012, slot.y), size: Vec3(1.05, 0.02, 0.85), material: 2)
            }
        }
    }

    /// Tapete verde onde o dinheiro das vendas se acumula.
    static func makeCashMat() -> ModelEntity {
        ModelFactory.model("cash.mat", colors: [Palette.cash, Palette.cashLight]) { b in
            b.box(center: Vec3(0, 0.03, 0), size: Vec3(1.8, 0.05, 1.5), material: 1)
            b.box(center: Vec3(0, 0.035, 0), size: Vec3(1.6, 0.05, 1.3), material: 0)
        }
    }

    /// Bandeja de madeira sob um monte de itens.
    static func makeTray(color: UInt32) -> ModelEntity {
        ModelFactory.model("tray", colors: [color]) { b in
            b.box(center: Vec3(0, 0.06, 0), size: Vec3(1.0, 0.12, 0.8), material: 0)
        }
    }

    // MARK: - Construções

    /// Galinheiro de telhado vermelho.
    static func makeCoop() -> ModelEntity {
        ModelFactory.model("building.coop", colors: [Palette.cream, Palette.red, Palette.dark, Palette.wood]) { b in
            b.box(center: Vec3(0, 0.55, 0), size: Vec3(2.2, 1.1, 1.6), material: 0)
            b.prism(base: Vec3(0, 1.1, 0), height: 0.85, bottomRadius: 1.75, topRadius: 0, sides: 4,
                    phase: .pi / 4, stretch: Vec2(1, 0.78), material: 1)
            b.box(center: Vec3(0, 0.32, 0.81), size: Vec3(0.5, 0.64, 0.04), material: 2)
            b.box(center: Vec3(0, 0.05, 1.1), size: Vec3(0.5, 0.1, 0.6), rotation: pitch(0.25), material: 3)
            // Cerquinha do terreiro.
            for i in 0..<6 {
                let x = -1.1 + Float(i) * 0.44
                b.box(center: Vec3(x, 0.2, 1.72), size: Vec3(0.07, 0.4, 0.07), material: 3)
            }
            b.box(center: Vec3(0, 0.3, 1.72), size: Vec3(2.3, 0.06, 0.04), material: 3)
        }
    }

    /// Galinha: corpo, cabeça, crista e bico numa malha só.
    static func makeChicken() -> ModelEntity {
        ModelFactory.model("chicken", colors: [Palette.white, Palette.red, Palette.yellow]) { b in
            b.ellipsoid(center: Vec3(0, 0.2, 0), radii: Vec3(0.16, 0.15, 0.2), segments: 6, rings: 4, material: 0)
            b.ellipsoid(center: Vec3(0, 0.38, 0.14), radii: Vec3(0.09, 0.09, 0.09), segments: 6, rings: 4, material: 0)
            b.box(center: Vec3(0, 0.49, 0.14), size: Vec3(0.04, 0.07, 0.1), material: 1)
            b.box(center: Vec3(0, 0.37, 0.25), size: Vec3(0.05, 0.04, 0.07), material: 2)
            b.box(center: Vec3(-0.05, 0.04, 0), size: Vec3(0.03, 0.08, 0.03), material: 2)
            b.box(center: Vec3(0.05, 0.04, 0), size: Vec3(0.03, 0.08, 0.03), material: 2)
        }
    }

    /// Padaria com forno aceso, chaminé e toldo.
    static func makeBakery() -> ModelEntity {
        ModelFactory.model("building.bakery", colors: [Palette.brick, Palette.brickDark, Palette.dark, Palette.fire, Palette.red]) { b in
            b.box(center: Vec3(0, 0.7, 0), size: Vec3(2.6, 1.4, 1.8), material: 0)
            b.box(center: Vec3(0, 1.47, 0), size: Vec3(2.9, 0.14, 2.1), material: 1)
            b.box(center: Vec3(0.8, 1.9, -0.4), size: Vec3(0.42, 0.8, 0.42), material: 1)
            b.box(center: Vec3(0, 0.55, 0.91), size: Vec3(0.95, 0.72, 0.04), material: 2)
            b.box(center: Vec3(0, 0.42, 0.93), size: Vec3(0.62, 0.34, 0.03), material: 3)
            b.box(center: Vec3(0, 1.18, 1.2), size: Vec3(2.6, 0.07, 0.7), rotation: pitch(0.3), material: 4)
        }
    }

    /// Celeiro vermelho com porta branca.
    static func makeBarn() -> ModelEntity {
        ModelFactory.model("building.barn", colors: [Palette.red, Palette.roofGray, Palette.cream]) { b in
            b.box(center: Vec3(0, 0.9, 0), size: Vec3(2.6, 1.8, 2.2), material: 0)
            b.prism(base: Vec3(0, 1.8, 0), height: 0.95, bottomRadius: 2.05, topRadius: 0, sides: 4,
                    phase: .pi / 4, stretch: Vec2(1, 0.86), material: 1)
            b.box(center: Vec3(0, 0.62, 1.11), size: Vec3(1.0, 1.24, 0.04), material: 2)
            b.box(center: Vec3(0, 1.74, 0), size: Vec3(2.7, 0.1, 2.3), material: 2)
        }
    }

    // MARK: - Obstáculos

    static func makeObstacle(_ kind: ObstacleKind) -> ModelEntity {
        switch kind {
        case .log:
            return ModelFactory.model("obstacle.log", colors: [Palette.wood, Palette.woodLight]) { b in
                // Tronco deitado ao longo do eixo z (bloqueia a passagem leste–oeste).
                let lay = pitch(.pi / 2)
                b.prism(base: Vec3(0, 0.42, -0.95), height: 1.9, bottomRadius: 0.42, topRadius: 0.42, sides: 8, rotation: lay, material: 0)
                b.prism(base: Vec3(0, 0.42, -0.97), height: 0.03, bottomRadius: 0.34, topRadius: 0.34, sides: 8, rotation: lay, material: 1)
                b.prism(base: Vec3(0, 0.42, 0.94), height: 0.03, bottomRadius: 0.34, topRadius: 0.34, sides: 8, rotation: lay, material: 1)
                b.prism(base: Vec3(0, 0.75, 0.2), height: 0.4, bottomRadius: 0.12, topRadius: 0.08, sides: 6, rotation: roll(0.5), material: 0)
            }
        case .deadTree:
            return ModelFactory.model("obstacle.deadTree", colors: [Palette.woodDark]) { b in
                b.prism(base: Vec3(0, 0, 0), height: 1.6, bottomRadius: 0.38, topRadius: 0.22, sides: 7, material: 0)
                b.prism(base: Vec3(0, 1.5, 0), height: 0.8, bottomRadius: 0.2, topRadius: 0.06, sides: 6, rotation: pitch(0.3), material: 0)
                b.prism(base: Vec3(0, 1.1, 0), height: 0.9, bottomRadius: 0.13, topRadius: 0.05, sides: 5, rotation: roll(0.95), material: 0)
                b.prism(base: Vec3(0, 0.9, 0), height: 0.8, bottomRadius: 0.12, topRadius: 0.05, sides: 5, rotation: roll(-1.05), material: 0)
            }
        case .debris:
            return ModelFactory.model("obstacle.debris", colors: [Palette.stone, Palette.stoneDark, Palette.wood]) { b in
                b.ellipsoid(center: Vec3(-0.55, 0.32, 0.1), radii: Vec3(0.55, 0.38, 0.5), segments: 6, rings: 4, material: 0)
                b.ellipsoid(center: Vec3(0.5, 0.42, -0.15), radii: Vec3(0.65, 0.48, 0.55), segments: 6, rings: 4, material: 1)
                b.ellipsoid(center: Vec3(0, 0.26, 0.6), radii: Vec3(0.4, 0.28, 0.34), segments: 6, rings: 4, material: 0)
                b.box(center: Vec3(0, 0.82, 0), size: Vec3(1.7, 0.08, 0.22), rotation: yaw(0.5), material: 2)
                b.box(center: Vec3(0.1, 0.7, 0.2), size: Vec3(1.4, 0.08, 0.2), rotation: yaw(-0.7), material: 2)
            }
        }
    }

    // MARK: - Pads

    /// Pad de compra: borda tracejada, fundo translúcido e preenchimento de progresso.
    /// Devolve a raiz e a entidade do preenchimento.
    static func makePad() -> (root: Entity, fill: Entity) {
        let size = GameConfig.Pads.size
        let root = Entity()

        let border = ModelFactory.model("pad.border", colors: [Palette.white]) { b in
            let half = size / 2
            let dash: Float = 0.3
            let thickness: Float = 0.08
            let count = 4
            let step = size / Float(count)
            for i in 0..<count {
                let along = -half + step * (Float(i) + 0.5)
                b.flatRect(center: Vec2(along, -half), size: Vec2(dash, thickness), y: 0.065, material: 0)
                b.flatRect(center: Vec2(along, half), size: Vec2(dash, thickness), y: 0.065, material: 0)
                b.flatRect(center: Vec2(-half, along), size: Vec2(thickness, dash), y: 0.065, material: 0)
                b.flatRect(center: Vec2(half, along), size: Vec2(thickness, dash), y: 0.065, material: 0)
            }
        }
        root.addChild(border)

        let back = ModelFactory.model("pad.back", material: ModelFactory.translucent(Palette.white, opacity: 0.22)) { b in
            b.flatRect(center: Vec2(0, 0), size: Vec2(size - 0.1, size - 0.1), y: 0.05, material: 0)
        }
        root.addChild(back)

        let fill = ModelFactory.model("pad.fill", material: ModelFactory.translucent(Palette.cash, opacity: 0.55)) { b in
            b.flatRect(center: Vec2(0, 0), size: Vec2(size - 0.1, size - 0.1), y: 0.056, material: 0)
        }
        fill.scale = Vec3(0.02, 1, 0.02)
        root.addChild(fill)

        return (root, fill)
    }

    // MARK: - Indicadores de objetivo

    /// Seta 3D que quica sobre o próximo objetivo (aponta para baixo).
    static func makeTargetArrow() -> ModelEntity {
        ModelFactory.model("indicator.target", colors: [Palette.yellow]) { b in
            b.prism(base: Vec3(0, 0, 0), height: 0.5, bottomRadius: 0, topRadius: 0.32, sides: 4, material: 0)
            b.prism(base: Vec3(0, 0.5, 0), height: 0.4, bottomRadius: 0.13, topRadius: 0.13, sides: 4, material: 0)
        }
    }

    /// Seta deitada no chão, apontando para +z.
    static func makeGroundArrow() -> ModelEntity {
        ModelFactory.model("indicator.ground", colors: [Palette.yellow]) { b in
            b.flatRect(center: Vec2(0, -0.1), size: Vec2(0.26, 0.6), y: 0.08, material: 0)
            b.flatTriangle(Vec2(-0.36, 0.2), Vec2(0.36, 0.2), Vec2(0, 0.72), y: 0.08, material: 0)
        }
    }
}
