import SwiftUI

/// Menu inicial / de pausa: jogar, ligar ou desligar o som e recomeçar do zero.
struct MenuView: View {
    let state: GameState
    @State private var confirmReset = false

    var body: some View {
        ZStack {
            Color.black.opacity(0.45)
                .ignoresSafeArea()

            VStack(spacing: 18) {
                Text("🌾")
                    .font(.system(size: 64))

                Text("Trigal do Tico")
                    .font(.system(size: 34, weight: .black, design: .rounded))
                    .foregroundStyle(Color(red: 0.45, green: 0.26, blue: 0.08))

                Text("Colha, venda e faça a fazenda crescer.")
                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                Button {
                    state.showMenu = false
                } label: {
                    Text(state.hasProgress ? "Continuar" : "Jogar")
                        .font(.system(size: 22, weight: .heavy, design: .rounded))
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Capsule().fill(Color(red: 0.2, green: 0.72, blue: 0.35)))
                }
                .buttonStyle(.plain)

                Button {
                    GameWorld.shared.toggleSound()
                } label: {
                    Label(state.soundOn ? "Som ligado" : "Som desligado",
                          systemImage: state.soundOn ? "speaker.wave.2.fill" : "speaker.slash.fill")
                        .font(.system(size: 16, weight: .bold, design: .rounded))
                        .foregroundStyle(.primary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(Capsule().fill(Color.gray.opacity(0.18)))
                }
                .buttonStyle(.plain)

                if state.hasProgress {
                    Button(role: .destructive) {
                        confirmReset = true
                    } label: {
                        Text("Novo jogo")
                            .font(.system(size: 15, weight: .bold, design: .rounded))
                    }
                }
            }
            .padding(26)
            .frame(maxWidth: 320)
            // O cartão é sempre claro; sem isto, no modo escuro os textos ficam brancos sobre creme.
            .environment(\.colorScheme, .light)
            .background(
                RoundedRectangle(cornerRadius: 28)
                    .fill(Color(red: 1, green: 0.97, blue: 0.88))
                    .shadow(color: .black.opacity(0.3), radius: 16, y: 8)
            )
            .padding(24)
        }
        .confirmationDialog("Apagar todo o progresso e começar de novo?",
                            isPresented: $confirmReset,
                            titleVisibility: .visible) {
            Button("Apagar e recomeçar", role: .destructive) {
                GameWorld.shared.resetGame()
                state.showMenu = false
            }
            Button("Cancelar", role: .cancel) {}
        }
    }
}
