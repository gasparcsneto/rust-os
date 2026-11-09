import Foundation
import simd

typealias Vec2 = SIMD2<Float>
typealias Vec3 = SIMD3<Float>

extension SIMD3 where Scalar == Float {
    /// Projeção no chão: (x, z).
    var xz: SIMD2<Float> { SIMD2<Float>(x, z) }
}

/// Converte um ponto do chão (x, z) em posição 3D na altura `y`.
func vec3(_ p: Vec2, _ y: Float = 0) -> Vec3 {
    Vec3(p.x, y, p.y)
}

func clamp01(_ t: Float) -> Float {
    min(1, max(0, t))
}

func smoothStep(_ t: Float) -> Float {
    let c = clamp01(t)
    return c * c * (3 - 2 * c)
}

/// Curva que passa um pouco do alvo e volta (efeito "pop").
func easeOutBack(_ t: Float) -> Float {
    let c1: Float = 1.70158
    let c3 = c1 + 1
    let u = clamp01(t) - 1
    return 1 + c3 * u * u * u + c1 * u * u
}

/// Interpola ângulos pelo caminho mais curto.
func lerpAngle(_ a: Float, _ b: Float, _ t: Float) -> Float {
    var d = (b - a).truncatingRemainder(dividingBy: 2 * .pi)
    if d > .pi { d -= 2 * .pi }
    if d < -.pi { d += 2 * .pi }
    return a + d * t
}

/// Retângulo no plano do chão.
struct Rect2: Sendable {
    var minX: Float
    var maxX: Float
    var minZ: Float
    var maxZ: Float

    var center: Vec2 { Vec2((minX + maxX) / 2, (minZ + maxZ) / 2) }
    var size: Vec2 { Vec2(maxX - minX, maxZ - minZ) }

    func contains(_ p: Vec2) -> Bool {
        p.x >= minX && p.x <= maxX && p.y >= minZ && p.y <= maxZ
    }
}

/// Gerador determinístico (SplitMix64) para cenário sempre igual entre execuções.
struct SeededRandom: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed &+ 0x9E37_79B9_7F4A_7C15
    }

    mutating func next() -> UInt64 {
        state = state &+ 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
