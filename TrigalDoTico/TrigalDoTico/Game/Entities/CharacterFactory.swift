import RealityKit
import simd

/// Cores e proporções de um boneco.
struct CharacterStyle: Sendable {
    var shirt: UInt32
    var pants: UInt32
    var skin: UInt32
    /// Cor do chapéu ou do cabelo.
    var headwear: UInt32
    var hasHat: Bool
    var scale: Float = 1

    static let player = CharacterStyle(shirt: 0xE8503A, pants: 0x2F5DA8, skin: Palette.skin, headwear: Palette.straw, hasHat: true)
    static let helper = CharacterStyle(shirt: 0x3FA7D6, pants: 0x5B4636, skin: 0xF2C38E, headwear: 0xF2F2F2, hasHat: true, scale: 0.88)

    /// Cliente com roupa sorteada.
    static func customer(using rng: inout SeededRandom) -> CharacterStyle {
        let shirts: [UInt32] = [0xF25F5C, 0x9B5DE5, 0x00BBF9, 0x00C49A, 0xF9A03F, 0xF15BB5, 0x5C7AEA, 0xFEE440]
        let pants: [UInt32] = [0x3D405B, 0x6D597A, 0x355070, 0x4A4E69]
        let skins: [UInt32] = [0xFFD6B0, 0xE8B58A, 0xC98E63, 0x8D5B3E]
        let hairs: [UInt32] = [0x3B2A20, 0x1F1F1F, 0xB5651D, 0xE3C16F, 0x7A3E2B]
        return CharacterStyle(shirt: shirts.randomElement(using: &rng) ?? 0xF25F5C,
                              pants: pants.randomElement(using: &rng) ?? 0x3D405B,
                              skin: skins.randomElement(using: &rng) ?? 0xFFD6B0,
                              headwear: hairs.randomElement(using: &rng) ?? 0x3B2A20,
                              hasHat: false,
                              scale: Float.random(in: 0.92...1.04, using: &rng))
    }
}

/// Monta bonecos de brinquedo com caixas e elipsoides.
/// Pernas e braços são entidades separadas (com o pivô na junta) para a animação procedural.
@MainActor
enum CharacterFactory {

    static func make(style: CharacterStyle, constrained: Bool) -> Entity {
        let root = Entity()
        root.addChild(ModelFactory.shadow(radius: 0.4))

        // Tronco + cabeça + chapéu/cabelo numa malha só.
        let bodyKey = style.hasHat ? "character.body.hat" : "character.body.hair"
        let hasHat = style.hasHat
        let body = ModelFactory.model(bodyKey, colors: [style.shirt, style.skin, style.headwear, Palette.dark]) { b in
            b.box(center: Vec3(0, 0.57, 0), size: Vec3(0.46, 0.46, 0.3), material: 0)
            b.ellipsoid(center: Vec3(0, 0.99, 0), radii: Vec3(0.21, 0.2, 0.2), material: 1)
            b.box(center: Vec3(-0.08, 1.0, 0.19), size: Vec3(0.045, 0.06, 0.03), material: 3)
            b.box(center: Vec3(0.08, 1.0, 0.19), size: Vec3(0.045, 0.06, 0.03), material: 3)
            if hasHat {
                b.prism(base: Vec3(0, 1.1, 0), height: 0.035, bottomRadius: 0.34, topRadius: 0.34, sides: 10, material: 2)
                b.prism(base: Vec3(0, 1.135, 0), height: 0.14, bottomRadius: 0.2, topRadius: 0.16, sides: 10, material: 2)
            } else {
                b.ellipsoid(center: Vec3(0, 1.09, -0.03), radii: Vec3(0.225, 0.13, 0.225), material: 2)
            }
        }
        root.addChild(body)

        let legLeft = limb(key: "character.leg", color: style.pants, size: Vec3(0.16, 0.34, 0.18))
        legLeft.position = Vec3(-0.11, 0.34, 0)
        root.addChild(legLeft)
        let legRight = limb(key: "character.leg", color: style.pants, size: Vec3(0.16, 0.34, 0.18))
        legRight.position = Vec3(0.11, 0.34, 0)
        root.addChild(legRight)

        let armLeft = limb(key: "character.arm", color: style.skin, size: Vec3(0.11, 0.34, 0.13))
        armLeft.position = Vec3(-0.29, 0.76, 0)
        body.addChild(armLeft)
        let armRight = limb(key: "character.arm", color: style.skin, size: Vec3(0.11, 0.34, 0.13))
        armRight.position = Vec3(0.29, 0.76, 0)
        body.addChild(armRight)

        root.scale = Vec3(repeating: style.scale)
        root.components.set(MotionComponent(radius: GameConfig.Player.radius, constrained: constrained))
        root.components.set(CharacterRigComponent(body: body, legLeft: legLeft, legRight: legRight, armLeft: armLeft, armRight: armRight))
        return root
    }

    /// Caixa com a origem no topo, para girar em torno da junta.
    private static func limb(key: String, color: UInt32, size: Vec3) -> ModelEntity {
        ModelFactory.model(key, colors: [color]) { b in
            b.box(center: Vec3(0, -size.y / 2, 0), size: size, material: 0)
        }
    }

    /// Foice: cabo de madeira e lâmina em gancho. Fica presa à mão direita.
    static func makeSickle() -> ModelEntity {
        let sickle = ModelFactory.model("tool.sickle", colors: [Palette.wood, Palette.steel]) { b in
            b.box(center: Vec3(0, 0, 0.12), size: Vec3(0.05, 0.05, 0.3), material: 0)
            b.box(center: Vec3(0.05, 0, 0.3), size: Vec3(0.16, 0.03, 0.07), rotation: simd_quatf(angle: -0.5, axis: Vec3(0, 1, 0)), material: 1)
            b.box(center: Vec3(0.16, 0, 0.24), size: Vec3(0.07, 0.03, 0.18), rotation: simd_quatf(angle: 0.35, axis: Vec3(0, 1, 0)), material: 1)
            b.box(center: Vec3(0.2, 0, 0.12), size: Vec3(0.06, 0.03, 0.12), rotation: simd_quatf(angle: 0.9, axis: Vec3(0, 1, 0)), material: 1)
        }
        sickle.position = Vec3(0, -0.33, 0.04)
        return sickle
    }

    /// Âncora da pilha nas costas (o boneco olha para +z, então "atrás" é -z).
    static func makeStackAnchor() -> Entity {
        let anchor = Entity()
        anchor.position = Vec3(0, 0.42, -0.36)
        return anchor
    }
}
