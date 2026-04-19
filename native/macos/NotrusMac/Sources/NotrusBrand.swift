import SwiftUI
import AppKit

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

enum NotrusBrandAssets {
    static func applicationIcon() -> NSImage {
        if let bundleImage = Bundle.main.url(forResource: "AppIcon", withExtension: "icns")
            .flatMap({ NSImage(contentsOf: $0) })
        {
            return bundleImage
        }

        let size: CGFloat = 512
        let image = NSImage(size: NSSize(width: size, height: size))
        image.lockFocus()

        let canvas = NSRect(x: 0, y: 0, width: size, height: size)
        NSColor.clear.setFill()
        canvas.fill()

        let shellRect = canvas.insetBy(dx: canvas.width * 0.06, dy: canvas.height * 0.06)
        let shellPath = NSBezierPath(
            roundedRect: shellRect,
            xRadius: canvas.width * 0.18,
            yRadius: canvas.height * 0.18
        )
        NSColor(srgbRed: 8.0 / 255.0, green: 21.0 / 255.0, blue: 29.0 / 255.0, alpha: 1).setFill()
        shellPath.fill()
        NSColor(white: 1, alpha: 0.08).setStroke()
        shellPath.lineWidth = max(1, canvas.width * 0.016)
        shellPath.stroke()

        let orbSize = canvas.width * 0.7
        let orbRect = NSRect(
            x: canvas.midX - orbSize / 2,
            y: canvas.midY - orbSize / 2,
            width: orbSize,
            height: orbSize
        )
        let orbPath = NSBezierPath(ovalIn: orbRect)
        NSColor(srgbRed: 142.0 / 255.0, green: 227.0 / 255.0, blue: 1.0, alpha: 1).setFill()
        orbPath.fill()

        let shieldWidth = canvas.width * 0.42
        let shieldHeight = canvas.height * 0.54
        let shieldRect = NSRect(
            x: canvas.midX - shieldWidth / 2,
            y: canvas.midY - shieldHeight / 2 + canvas.height * 0.01,
            width: shieldWidth,
            height: shieldHeight
        )
        let shieldPath = NSBezierPath()
        let top = NSPoint(x: shieldRect.midX, y: shieldRect.minY)
        let rightShoulder = NSPoint(x: shieldRect.maxX, y: shieldRect.minY + shieldRect.height * 0.19)
        let rightGate = NSPoint(x: shieldRect.maxX, y: shieldRect.minY + shieldRect.height * 0.46)
        let tip = NSPoint(x: shieldRect.midX, y: shieldRect.maxY)
        let leftGate = NSPoint(x: shieldRect.minX, y: shieldRect.minY + shieldRect.height * 0.46)
        let leftShoulder = NSPoint(x: shieldRect.minX, y: shieldRect.minY + shieldRect.height * 0.19)
        shieldPath.move(to: top)
        shieldPath.line(to: NSPoint(x: shieldRect.maxX * 0.94 + shieldRect.minX * 0.06, y: shieldRect.minY + shieldRect.height * 0.08))
        shieldPath.line(to: rightShoulder)
        shieldPath.line(to: rightGate)
        shieldPath.curve(
            to: tip,
            controlPoint1: NSPoint(x: shieldRect.maxX, y: shieldRect.minY + shieldRect.height * 0.72),
            controlPoint2: NSPoint(x: shieldRect.midX + shieldRect.width * 0.18, y: shieldRect.maxY)
        )
        shieldPath.curve(
            to: leftGate,
            controlPoint1: NSPoint(x: shieldRect.midX - shieldRect.width * 0.18, y: shieldRect.maxY),
            controlPoint2: NSPoint(x: shieldRect.minX, y: shieldRect.minY + shieldRect.height * 0.72)
        )
        shieldPath.line(to: leftShoulder)
        shieldPath.line(to: NSPoint(x: shieldRect.minX + shieldRect.width * 0.06, y: shieldRect.minY + shieldRect.height * 0.08))
        shieldPath.close()
        NSColor(srgbRed: 8.0 / 255.0, green: 21.0 / 255.0, blue: 29.0 / 255.0, alpha: 1).setFill()
        shieldPath.fill()

        image.unlockFocus()
        return image
    }
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
