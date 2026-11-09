import RealityKit
import UIKit

extension UIColor {
    /// Cor a partir de 0xRRGGBB.
    convenience init(hex: UInt32, alpha: CGFloat = 1) {
        self.init(red: CGFloat((hex >> 16) & 0xFF) / 255,
                  green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255,
                  alpha: alpha)
    }
}

/// Paleta de cores chapadas do jogo (0xRRGGBB).
enum Palette {
    static let grass: UInt32 = 0x8FD14F
    static let grassDark: UInt32 = 0x4E9A3A
    static let bush: UInt32 = 0x3C8031
    static let soil: UInt32 = 0xB9793E
    static let path: UInt32 = 0xEBD9A7
    static let wheat: UInt32 = 0xF7C531
    static let wheatLight: UInt32 = 0xFFE27A
    static let wheatBand: UInt32 = 0xC0562B
    static let eggShell: UInt32 = 0xFFF8EA
    static let eggCup: UInt32 = 0x8FB6D9
    static let pieCrust: UInt32 = 0xE2A857
    static let pieFilling: UInt32 = 0xC8334A
    static let cash: UInt32 = 0x3FBF5F
    static let cashLight: UInt32 = 0xB9F2C4
    static let wood: UInt32 = 0x8B5A2B
    static let woodLight: UInt32 = 0xE0B97D
    static let woodDark: UInt32 = 0x6E4B33
    static let stone: UInt32 = 0x9AA3AD
    static let stoneDark: UInt32 = 0x77808A
    static let counter: UInt32 = 0x2F80ED
    static let counterBelt: UInt32 = 0x1B4F9C
    static let counterPlate: UInt32 = 0xEAF2FF
    static let white: UInt32 = 0xFFFFFF
    static let cream: UInt32 = 0xFFF1C9
    static let red: UInt32 = 0xD64541
    static let roofGray: UInt32 = 0x7F8C8D
    static let dark: UInt32 = 0x2B2B2B
    static let brick: UInt32 = 0xE8A15B
    static let brickDark: UInt32 = 0x8E4B2B
    static let fire: UInt32 = 0xFF7A1A
    static let yellow: UInt32 = 0xFFD60A
    static let steel: UInt32 = 0xC9D1D9
    static let skin: UInt32 = 0xFFCC99
    static let straw: UInt32 = 0xE8C56A
}

/// Cache de malhas e materiais. Todas as entidades do mesmo tipo compartilham os mesmos recursos.
@MainActor
enum ModelFactory {
    private static var meshes: [String: MeshResource] = [:]
    private static var materials: [UInt32: SimpleMaterial] = [:]
    private static var shadowMaterial: UnlitMaterial?

    /// Material fosco de cor chapada.
    static func material(_ hex: UInt32) -> SimpleMaterial {
        if let cached = materials[hex] { return cached }
        let created = SimpleMaterial(color: UIColor(hex: hex), roughness: 0.9, isMetallic: false)
        materials[hex] = created
        return created
    }

    /// Material sem iluminação e translúcido (sombras, preenchimento dos pads).
    static func translucent(_ hex: UInt32, opacity: Float) -> UnlitMaterial {
        var created = UnlitMaterial(color: UIColor(hex: hex))
        created.blending = .transparent(opacity: .init(floatLiteral: opacity))
        return created
    }

    /// Malha em cache; `build` só roda na primeira vez que a chave aparece.
    static func mesh(_ key: String, build: (inout MeshBuilder) -> Void) -> MeshResource {
        if let cached = meshes[key] { return cached }
        var builder = MeshBuilder()
        build(&builder)
        let created = builder.makeResource()
        meshes[key] = created
        return created
    }

    /// Modelo com uma cor por índice de material usado em `build`.
    static func model(_ key: String, colors: [UInt32], build: (inout MeshBuilder) -> Void) -> ModelEntity {
        let resource = mesh(key, build: build)
        var list: [any RealityKit.Material] = []
        for color in colors { list.append(material(color)) }
        return ModelEntity(mesh: resource, materials: list)
    }

    /// Modelo com um único material já pronto.
    static func model(_ key: String, material: any RealityKit.Material, build: (inout MeshBuilder) -> Void) -> ModelEntity {
        ModelEntity(mesh: mesh(key, build: build), materials: [material])
    }

    /// Sombra redonda simples, deitada no chão.
    static func shadow(radius: Float) -> ModelEntity {
        let material: UnlitMaterial
        if let cached = shadowMaterial {
            material = cached
        } else {
            material = translucent(0x000000, opacity: 0.22)
            shadowMaterial = material
        }
        let entity = model("shadow", material: material) { b in
            b.prism(base: Vec3(0, 0, 0), height: 0.004, bottomRadius: 1, topRadius: 1, sides: 12, material: 0)
        }
        entity.position = Vec3(0, 0.07, 0)
        entity.scale = Vec3(radius, 1, radius)
        return entity
    }
}
