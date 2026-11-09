import SwiftUI

/// Desenha os textos que os sistemas ECS projetaram na tela:
/// balões dos clientes, preços dos pads, vida dos obstáculos e feedbacks.
struct LabelsOverlay: View {
    let state: GameState

    var body: some View {
        ZStack {
            ForEach(state.labels) { label in
                LabelView(label: label)
                    .fixedSize()
                    .opacity(label.opacity)
                    .position(x: label.x, y: label.y)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .allowsHitTesting(false)
    }
}

struct LabelView: View {
    let label: ScreenLabel

    var body: some View {
        switch label.style {
        case .bubble:
            Text(label.text)
                .font(.system(size: 15, weight: .heavy, design: .rounded))
                .foregroundStyle(.black)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(.white)
                        .shadow(color: .black.opacity(0.25), radius: 2, y: 1)
                )
                .overlay(alignment: .bottom) {
                    BubbleTail()
                        .fill(.white)
                        .frame(width: 12, height: 7)
                        .offset(y: 6)
                }

        case .pad:
            VStack(spacing: 1) {
                if let icon = label.icon {
                    PadIconView(kind: icon)
                }
                if !label.detail.isEmpty {
                    OutlinedText(text: label.detail, size: 11, color: .white)
                }
                HStack(spacing: 4) {
                    CashIcon(width: 20)
                    OutlinedText(text: label.text, size: 19, color: .white)
                }
            }

        case .health:
            OutlinedText(text: label.text, size: 20, color: .white)

        case .max:
            OutlinedText(text: label.text, size: 22, color: Color(red: 1, green: 0.25, blue: 0.2))

        case .gain:
            OutlinedText(text: label.text, size: 20, color: Color(red: 0.55, green: 1, blue: 0.45))

        case .warning:
            OutlinedText(text: label.text, size: 19, color: Color(red: 1, green: 0.22, blue: 0.18))

        case .tag:
            Text(label.text)
                .font(.system(size: 17))
                .frame(width: 32, height: 32)
                .background(
                    Circle()
                        .fill(.white.opacity(0.92))
                        .shadow(color: .black.opacity(0.25), radius: 2, y: 1)
                )
        }
    }
}

/// Texto arredondado com contorno escuro, legível sobre qualquer fundo.
struct OutlinedText: View {
    let text: String
    let size: CGFloat
    let color: Color

    var body: some View {
        Text(text)
            .font(.system(size: size, weight: .black, design: .rounded))
            .foregroundStyle(color)
            .shadow(color: .black.opacity(0.9), radius: 0, x: 1, y: 1)
            .shadow(color: .black.opacity(0.9), radius: 0, x: -1, y: 1)
            .shadow(color: .black.opacity(0.9), radius: 0, x: 1, y: -1)
            .shadow(color: .black.opacity(0.9), radius: 0, x: -1, y: -1)
    }
}

/// Bico do balão de pedido.
struct BubbleTail: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
        path.closeSubpath()
        return path
    }
}

/// Ícone de cada tipo de pad.
struct PadIconView: View {
    let kind: PadKind

    var body: some View {
        switch kind {
        case .sickle:
            // Seta para cima + foice.
            HStack(spacing: 2) {
                Image(systemName: "arrow.up")
                    .font(.system(size: 17, weight: .black))
                SickleShape()
                    .frame(width: 26, height: 26)
            }
            .foregroundStyle(.white)
            .shadow(color: .black.opacity(0.8), radius: 1, y: 1)
        default:
            Text(emoji)
                .font(.system(size: 26))
                .shadow(color: .black.opacity(0.5), radius: 1, y: 1)
        }
    }

    private var emoji: String {
        switch kind {
        case .hireHelper: return "🧑‍🌾"
        case .sickle: return "⬆️"
        case .coop: return "🐔"
        case .bakery: return "🥧"
        case .barn: return "🛖"
        case .barnUpgrade: return "📦"
        case .wateringCan: return "💧"
        case .boots: return "🥾"
        case .oven: return "🔥"
        case .training: return "💪"
        case .promo: return "🏷️"
        }
    }
}

/// Foice desenhada com um arco (lâmina) e um traço (cabo).
struct SickleShape: Shape {
    func path(in rect: CGRect) -> Path {
        let w = rect.width
        let h = rect.height
        var blade = Path()
        blade.addArc(center: CGPoint(x: rect.minX + w * 0.56, y: rect.minY + h * 0.46),
                     radius: w * 0.33,
                     startAngle: .degrees(150),
                     endAngle: .degrees(20),
                     clockwise: false)
        var handle = Path()
        handle.move(to: CGPoint(x: rect.minX + w * 0.27, y: rect.minY + h * 0.63))
        handle.addLine(to: CGPoint(x: rect.minX + w * 0.12, y: rect.minY + h * 0.94))

        var path = Path()
        path.addPath(blade.strokedPath(StrokeStyle(lineWidth: w * 0.13, lineCap: .round)))
        path.addPath(handle.strokedPath(StrokeStyle(lineWidth: w * 0.17, lineCap: .round)))
        return path
    }
}
