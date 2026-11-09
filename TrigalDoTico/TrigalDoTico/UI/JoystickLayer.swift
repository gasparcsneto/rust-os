import SwiftUI

/// Joystick virtual flutuante: aparece onde o dedo toca e some ao soltar.
/// A velocidade do personagem é proporcional à distância do arraste.
struct JoystickLayer: View {

    /// Arraste em andamento: onde o dedo tocou e o deslocamento (já limitado ao raio).
    private struct Drag: Equatable {
        var origin: CGPoint
        var knob: CGSize
    }

    /// `@GestureState` volta sozinho para nil quando o gesto termina *ou é cancelado*
    /// (alerta do sistema, central de controle, app indo para segundo plano).
    /// Com `onEnded` o personagem continuava andando sozinho nesses casos.
    @GestureState private var drag: Drag? = nil

    private let radius = CGFloat(GameConfig.Controls.joystickRadius)

    var body: some View {
        ZStack {
            // Área de toque: a tela inteira.
            Color.clear
                .contentShape(Rectangle())

            if let drag {
                Circle()
                    .fill(.white.opacity(0.18))
                    .overlay(Circle().stroke(.white.opacity(0.55), lineWidth: 3))
                    .frame(width: radius * 2, height: radius * 2)
                    .position(drag.origin)

                Circle()
                    .fill(.white.opacity(0.85))
                    .frame(width: 52, height: 52)
                    .shadow(color: .black.opacity(0.25), radius: 4, y: 2)
                    .position(x: drag.origin.x + drag.knob.width, y: drag.origin.y + drag.knob.height)
            }
        }
        .gesture(
            DragGesture(minimumDistance: 0)
                .updating($drag) { value, state, _ in
                    var offset = value.translation
                    let length = hypot(offset.width, offset.height)
                    if length > radius {
                        offset.width *= radius / length
                        offset.height *= radius / length
                    }
                    state = Drag(origin: value.startLocation, knob: offset)
                }
        )
        .onChange(of: drag) { _, current in
            if let current {
                GameWorld.shared.input = SIMD2<Float>(Float(current.knob.width / radius),
                                                      Float(current.knob.height / radius))
            } else {
                GameWorld.shared.input = .zero
            }
        }
        .onDisappear {
            GameWorld.shared.input = .zero
        }
    }
}
