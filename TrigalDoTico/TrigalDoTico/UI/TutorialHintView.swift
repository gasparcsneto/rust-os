import SwiftUI

/// Dica inicial: uma mão animada arrastando e o texto "Arraste para mover".
/// Some assim que o jogador move o personagem pela primeira vez.
struct TutorialHintView: View {
    @State private var dragging = false

    var body: some View {
        VStack(spacing: 14) {
            Spacer()

            ZStack {
                Circle()
                    .stroke(.white.opacity(0.7), style: StrokeStyle(lineWidth: 3, dash: [7, 7]))
                    .frame(width: 128, height: 128)

                Text("👆")
                    .font(.system(size: 56))
                    .offset(x: dragging ? 38 : -38, y: dragging ? -20 : 24)
            }

            Text("Arraste para mover")
                .font(.system(size: 20, weight: .heavy, design: .rounded))
                .foregroundStyle(.white)
                .padding(.horizontal, 18)
                .padding(.vertical, 9)
                .background(Capsule().fill(.black.opacity(0.55)))
        }
        .padding(.bottom, 110)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .allowsHitTesting(false)
        .onAppear {
            withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) {
                dragging = true
            }
        }
    }
}
