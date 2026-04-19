import AppKit
import Foundation

let arguments = CommandLine.arguments
guard arguments.count == 2 else {
    fputs("usage: render-mac-icon.swift <iconset-dir>\n", stderr)
    exit(1)
}

let outputDirectory = URL(fileURLWithPath: arguments[1], isDirectory: true)

let darkShell = NSColor(srgbRed: 8.0 / 255.0, green: 21.0 / 255.0, blue: 29.0 / 255.0, alpha: 1)
let cyanOrb = NSColor(srgbRed: 142.0 / 255.0, green: 227.0 / 255.0, blue: 1.0, alpha: 1)
let rim = NSColor(white: 1, alpha: 0.08)

let iconEntries: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]

do {
    try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
    for (filename, dimension) in iconEntries {
        let data = try renderIconPNG(size: dimension)
        try data.write(to: outputDirectory.appendingPathComponent(filename), options: .atomic)
    }
} catch {
    fputs("\(error.localizedDescription)\n", stderr)
    exit(1)
}

func renderIconPNG(size: Int) throws -> Data {
    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size,
        pixelsHigh: size,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else {
        throw NSError(domain: "render-mac-icon", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unable to allocate bitmap"])
    }

    bitmap.size = NSSize(width: size, height: size)

    NSGraphicsContext.saveGraphicsState()
    guard let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
        throw NSError(domain: "render-mac-icon", code: 2, userInfo: [NSLocalizedDescriptionKey: "Unable to create graphics context"])
    }
    NSGraphicsContext.current = context
    context.cgContext.setShouldAntialias(true)
    context.cgContext.interpolationQuality = .high

    let canvas = NSRect(x: 0, y: 0, width: CGFloat(size), height: CGFloat(size))
    NSColor.clear.setFill()
    NSBezierPath(rect: canvas).fill()

    let shellRect = canvas.insetBy(dx: canvas.width * 0.06, dy: canvas.height * 0.06)
    let shellPath = NSBezierPath(roundedRect: shellRect, xRadius: canvas.width * 0.18, yRadius: canvas.height * 0.18)
    darkShell.setFill()
    shellPath.fill()
    rim.setStroke()
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
    cyanOrb.setFill()
    orbPath.fill()

    let shieldWidth = canvas.width * 0.42
    let shieldHeight = canvas.height * 0.54
    let shieldRect = NSRect(
        x: canvas.midX - shieldWidth / 2,
        y: canvas.midY - shieldHeight / 2 + canvas.height * 0.01,
        width: shieldWidth,
        height: shieldHeight
    )
    let shield = shieldPath(in: shieldRect)
    darkShell.setFill()
    shield.fill()

    NSGraphicsContext.restoreGraphicsState()

    guard let data = bitmap.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "render-mac-icon", code: 3, userInfo: [NSLocalizedDescriptionKey: "Unable to encode PNG"])
    }
    return data
}

func shieldPath(in rect: NSRect) -> NSBezierPath {
    let path = NSBezierPath()

    let top = NSPoint(x: rect.midX, y: rect.minY)
    let rightShoulder = NSPoint(x: rect.maxX, y: rect.minY + rect.height * 0.19)
    let rightGate = NSPoint(x: rect.maxX, y: rect.minY + rect.height * 0.46)
    let tip = NSPoint(x: rect.midX, y: rect.maxY)
    let leftGate = NSPoint(x: rect.minX, y: rect.minY + rect.height * 0.46)
    let leftShoulder = NSPoint(x: rect.minX, y: rect.minY + rect.height * 0.19)

    path.move(to: top)
    path.line(to: NSPoint(x: rect.maxX * 0.94 + rect.minX * 0.06, y: rect.minY + rect.height * 0.08))
    path.line(to: rightShoulder)
    path.line(to: rightGate)
    path.curve(
        to: tip,
        controlPoint1: NSPoint(x: rect.maxX, y: rect.minY + rect.height * 0.72),
        controlPoint2: NSPoint(x: rect.midX + rect.width * 0.18, y: rect.maxY)
    )
    path.curve(
        to: leftGate,
        controlPoint1: NSPoint(x: rect.midX - rect.width * 0.18, y: rect.maxY),
        controlPoint2: NSPoint(x: rect.minX, y: rect.minY + rect.height * 0.72)
    )
    path.line(to: leftShoulder)
    path.line(to: NSPoint(x: rect.minX + rect.width * 0.06, y: rect.minY + rect.height * 0.08))
    path.close()

    return path
}
