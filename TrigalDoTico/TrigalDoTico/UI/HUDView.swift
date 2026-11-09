import SwiftUI

/// HUD sobreposto: contadores em pílulas no canto superior direito,
/// botão de menu no canto superior esquerdo e botão de som no canto inferior esquerdo.
struct HUDView: View {
    let state: GameState

    var body: some View {
        VStack {
            HStack(alignment: .top) {
                RoundButton(systemName: "line.3.horizontal") {
                    state.showMenu = true
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 8) {
                    CounterPill(value: state.money) { CashIcon(width: 24) }
                    CounterPill(value: state.wheat) { Text("🌾") }
                    CounterPill(value: state.eggs) { Text("🥚") }
                    CounterPill(value: state.pies) { Text("🥧") }
                }
            }
            Spacer()
            HStack {
                RoundButton(systemName: state.soundOn ? "speaker.wave.2.fill" : "speaker.slash.fill") {
                    GameWorld.shared.toggleSound()
                }
                Spacer()
            }
        }
        .padding(.horizontal, 14)
        .padding(.top, 6)
        .padding(.bottom, 14)
    }
}

/// Contador em "pílula" escura. O número anima (count-up) quando muda.
struct CounterPill<Icon: View>: View {
    let value: Int
    @ViewBuilder let icon: () -> Icon

    var body: some View {
        HStack(spacing: 8) {
            icon()
                .font(.system(size: 18))
                .frame(width: 26, height: 22)
            Text("\(value)")
                .font(.system(size: 18, weight: .heavy, design: .rounded))
                .monospacedDigit()
                .foregroundStyle(.white)
                .contentTransition(.numericText(value: Double(value)))
                .animation(.snappy(duration: 0.35), value: value)
                .frame(minWidth: 34, alignment: .trailing)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(Capsule().fill(.black.opacity(0.55)))
    }
}

/// Nota verde desenhada com formas (ícone do dinheiro).
struct CashIcon: View {
    var width: CGFloat = 24

    var body: some View {
        RoundedRectangle(cornerRadius: width * 0.14)
            .fill(Color(red: 0.25, green: 0.75, blue: 0.37))
            .overlay(
                RoundedRectangle(cornerRadius: width * 0.14)
                    .stroke(Color(red: 0.73, green: 0.95, blue: 0.77), lineWidth: max(1, width * 0.07))
            )
            .overlay(
                Text("$")
                    .font(.system(size: width * 0.5, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
            )
            .frame(width: width, height: width * 0.62)
    }
}

/// Botão redondo escuro com um SF Symbol.
struct RoundButton: View {
    let systemName: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 18, weight: .bold))
                .foregroundStyle(.white)
                .frame(width: 46, height: 46)
                .background(Circle().fill(.black.opacity(0.55)))
        }
        .buttonStyle(.plain)
    }
}
