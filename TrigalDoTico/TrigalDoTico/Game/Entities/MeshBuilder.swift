import RealityKit
import simd

/// Monta malhas low-poly com sombreamento chapado (um normal por face).
/// Cada `material` vira uma parte da malha, então um único `ModelEntity`
/// pode ter várias cores sem custar várias entidades.
struct MeshBuilder {

    private struct Part {
        var positions: [Vec3] = []
        var normals: [Vec3] = []
        var indices: [UInt32] = []
    }

    private var parts: [Part] = []

    static let noRotation = simd_quatf(ix: 0, iy: 0, iz: 0, r: 1)

    // MARK: - Primitivas básicas

    /// Adiciona um triângulo. A ordem dos vértices é corrigida para que a face
    /// aponte para longe de `center` (assim nunca fica invisível por culling).
    mutating func triangle(_ a: Vec3, _ b: Vec3, _ c: Vec3, outwardFrom center: Vec3, material: Int) {
        var p1 = b
        var p2 = c
        var normal = simd_cross(p1 - a, p2 - a)
        let length = simd_length(normal)
        guard length > 1e-8 else { return }
        normal = normal / length
        let centroid = (a + p1 + p2) / 3
        if simd_dot(normal, centroid - center) < 0 {
            swap(&p1, &p2)
            normal = -normal
        }
        while parts.count <= material { parts.append(Part()) }
        let base = UInt32(parts[material].positions.count)
        parts[material].positions.append(a)
        parts[material].positions.append(p1)
        parts[material].positions.append(p2)
        parts[material].normals.append(normal)
        parts[material].normals.append(normal)
        parts[material].normals.append(normal)
        parts[material].indices.append(base)
        parts[material].indices.append(base + 1)
        parts[material].indices.append(base + 2)
    }

    mutating func quad(_ a: Vec3, _ b: Vec3, _ c: Vec3, _ d: Vec3, outwardFrom center: Vec3, material: Int) {
        triangle(a, b, c, outwardFrom: center, material: material)
        triangle(a, c, d, outwardFrom: center, material: material)
    }

    // MARK: - Sólidos

    /// Caixa centrada em `center`.
    mutating func box(center: Vec3, size: Vec3, rotation: simd_quatf = MeshBuilder.noRotation, material: Int) {
        let half = size / 2
        var corners: [Vec3] = []
        for sz in [Float(-1), Float(1)] {
            for sy in [Float(-1), Float(1)] {
                for sx in [Float(-1), Float(1)] {
                    corners.append(center + rotation.act(Vec3(sx * half.x, sy * half.y, sz * half.z)))
                }
            }
        }
        // Índices: bit 0 = x, bit 1 = y, bit 2 = z.
        let faces: [[Int]] = [
            [0, 1, 3, 2], [4, 5, 7, 6],   // z-, z+
            [0, 1, 5, 4], [2, 3, 7, 6],   // y-, y+
            [0, 2, 6, 4], [1, 3, 7, 5],   // x-, x+
        ]
        for f in faces {
            quad(corners[f[0]], corners[f[1]], corners[f[2]], corners[f[3]], outwardFrom: center, material: material)
        }
    }

    /// Prisma / tronco de cone com eixo em +y a partir de `base`.
    /// Raio 0 em uma das pontas vira um cone. `stretch` deforma a seção em (x, z).
    mutating func prism(base: Vec3,
                        height: Float,
                        bottomRadius: Float,
                        topRadius: Float,
                        sides: Int,
                        phase: Float = 0,
                        stretch: Vec2 = Vec2(1, 1),
                        rotation: simd_quatf = MeshBuilder.noRotation,
                        material: Int) {
        let middle = base + rotation.act(Vec3(0, height / 2, 0))
        let topCenter = base + rotation.act(Vec3(0, height, 0))
        var bottom: [Vec3] = []
        var top: [Vec3] = []
        for i in 0...sides {
            let angle = phase + Float(i) / Float(sides) * 2 * .pi
            let dx = cos(angle) * stretch.x
            let dz = sin(angle) * stretch.y
            bottom.append(base + rotation.act(Vec3(dx * bottomRadius, 0, dz * bottomRadius)))
            top.append(base + rotation.act(Vec3(dx * topRadius, height, dz * topRadius)))
        }
        for i in 0..<sides {
            quad(bottom[i], bottom[i + 1], top[i + 1], top[i], outwardFrom: middle, material: material)
            triangle(base, bottom[i], bottom[i + 1], outwardFrom: middle, material: material)
            triangle(topCenter, top[i], top[i + 1], outwardFrom: middle, material: material)
        }
    }

    /// Elipsoide facetado.
    mutating func ellipsoid(center: Vec3, radii: Vec3, segments: Int = 8, rings: Int = 5, material: Int) {
        func point(_ ring: Int, _ segment: Int) -> Vec3 {
            let latitude = -Float.pi / 2 + Float(ring) / Float(rings) * .pi
            let longitude = Float(segment) / Float(segments) * 2 * .pi
            return center + Vec3(cos(latitude) * cos(longitude) * radii.x,
                                 sin(latitude) * radii.y,
                                 cos(latitude) * sin(longitude) * radii.z)
        }
        for ring in 0..<rings {
            for segment in 0..<segments {
                quad(point(ring, segment), point(ring, segment + 1),
                     point(ring + 1, segment + 1), point(ring + 1, segment),
                     outwardFrom: center, material: material)
            }
        }
    }

    // MARK: - Formas planas (viradas para cima)

    /// Retângulo deitado no chão, na altura `y`.
    mutating func flatRect(center: Vec2, size: Vec2, y: Float, yaw: Float = 0, material: Int) {
        let c = cos(yaw)
        let s = sin(yaw)
        func corner(_ sx: Float, _ sz: Float) -> Vec3 {
            let lx = sx * size.x / 2
            let lz = sz * size.y / 2
            return Vec3(center.x + lx * c + lz * s, y, center.y - lx * s + lz * c)
        }
        let below = Vec3(center.x, y - 1, center.y)
        quad(corner(-1, -1), corner(1, -1), corner(1, 1), corner(-1, 1), outwardFrom: below, material: material)
    }

    /// Triângulo deitado no chão, na altura `y`.
    mutating func flatTriangle(_ a: Vec2, _ b: Vec2, _ c: Vec2, y: Float, material: Int) {
        let center = (a + b + c) / 3
        triangle(vec3(a, y), vec3(b, y), vec3(c, y), outwardFrom: vec3(center, y - 1), material: material)
    }

    // MARK: - Resultado

    /// Gera o `MeshResource`. A parte de índice `i` usa o material `i` do `ModelEntity`.
    @MainActor
    func makeResource() -> MeshResource {
        var descriptors: [MeshDescriptor] = []
        for (index, part) in parts.enumerated() where !part.positions.isEmpty {
            var descriptor = MeshDescriptor(name: "part\(index)")
            descriptor.positions = MeshBuffers.Positions(part.positions)
            descriptor.normals = MeshBuffers.Normals(part.normals)
            descriptor.primitives = .triangles(part.indices)
            descriptor.materials = .allFaces(UInt32(index))
            descriptors.append(descriptor)
        }
        if !descriptors.isEmpty, let mesh = try? MeshResource.generate(from: descriptors) {
            return mesh
        }
        return MeshResource.generateBox(size: 0.2)
    }
}
