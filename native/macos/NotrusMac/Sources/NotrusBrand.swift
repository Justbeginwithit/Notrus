import SwiftUI

struct NotrusLogoMark: View {
    var size: CGFloat = 56

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .fill(NotrusBrandPalette.shell)

            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .strokeBorder(Color.white.opacity(0.08), lineWidth: max(1, size * 0.024))

            Circle()
                .fill(NotrusBrandPalette.orb)
                .frame(width: size * 0.7, height: size * 0.7)

            NotrusShieldGlyph()
                .fill(NotrusBrandPalette.core)
                .frame(width: size * 0.42, height: size * 0.54)
        }
        .frame(width: size, height: size)
        .shadow(color: .black.opacity(0.22), radius: size * 0.16, x: 0, y: size * 0.08)
    }
}

struct NotrusBrandLockup: View {
    var title: String = "Notrus Mac"
    var subtitle: String? = "Native secure messaging"
    var compact: Bool = false

    var body: some View {
        HStack(spacing: compact ? 12 : 16) {
            NotrusLogoMark(size: compact ? 42 : 56)

            VStack(alignment: .leading, spacing: compact ? 2 : 4) {
                Text(title)
                    .font(.system(size: compact ? 20 : 28, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: compact ? 11 : 13, weight: .medium, design: .rounded))
                        .foregroundStyle(NotrusPalette.muted)
                }
            }
        }
    }
}

enum NotrusBrandPalette {
    static let shell = Color(red: 8 / 255, green: 21 / 255, blue: 29 / 255)
    static let orb = Color(red: 142 / 255, green: 227 / 255, blue: 1.0)
    static let core = Color(red: 8 / 255, green: 21 / 255, blue: 29 / 255)
}

private struct NotrusShieldGlyph: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()

        let top = CGPoint(x: rect.midX, y: rect.minY)
        let rightShoulder = CGPoint(x: rect.maxX, y: rect.minY + rect.height * 0.19)
        let rightGate = CGPoint(x: rect.maxX, y: rect.minY + rect.height * 0.46)
        let tip = CGPoint(x: rect.midX, y: rect.maxY)
        let leftGate = CGPoint(x: rect.minX, y: rect.minY + rect.height * 0.46)
        let leftShoulder = CGPoint(x: rect.minX, y: rect.minY + rect.height * 0.19)

        path.move(to: top)
        path.addLine(to: CGPoint(x: rect.maxX * 0.94 + rect.minX * 0.06, y: rect.minY + rect.height * 0.08))
        path.addLine(to: rightShoulder)
        path.addLine(to: rightGate)
        path.addCurve(
            to: tip,
            control1: CGPoint(x: rect.maxX, y: rect.minY + rect.height * 0.72),
            control2: CGPoint(x: rect.midX + rect.width * 0.18, y: rect.maxY)
        )
        path.addCurve(
            to: leftGate,
            control1: CGPoint(x: rect.midX - rect.width * 0.18, y: rect.maxY),
            control2: CGPoint(x: rect.minX, y: rect.minY + rect.height * 0.72)
        )
        path.addLine(to: leftShoulder)
        path.addLine(to: CGPoint(x: rect.minX + rect.width * 0.06, y: rect.minY + rect.height * 0.08))
        path.closeSubpath()

        return path
    }
}
