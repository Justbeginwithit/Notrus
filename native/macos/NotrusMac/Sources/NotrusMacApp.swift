import AppKit
import SwiftUI
import UniformTypeIdentifiers

@main
struct NotrusMacApp: App {
    @StateObject private var model = AppModel()
    @AppStorage("NotrusMac.appearanceMode") private var appearanceModeRaw = AppAppearanceMode.system.rawValue

    init() {
        NSApplication.shared.applicationIconImage = NotrusBrandAssets.applicationIcon()
    }

    var body: some Scene {
        WindowGroup("Notrus Mac") {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 1080, minHeight: 760)
                .tint(NotrusPalette.accent)
                .preferredColorScheme(AppAppearanceMode(rawValue: appearanceModeRaw)?.colorScheme)
                .task {
                    await model.bootstrap()
                }
        }
    }
}

enum AppAppearanceMode: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    var id: String { rawValue }

    var title: String {
        switch self {
        case .system:
            return "System"
        case .light:
            return "Light"
        case .dark:
            return "Dark"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .system:
            return nil
        case .light:
            return .light
        case .dark:
            return .dark
        }
    }
}

enum NotrusPalette {
    static let accent = adaptive(light: rgb(0.11, 0.66, 0.60), dark: rgb(0.27, 0.78, 0.72))
    static let accentSoft = adaptive(light: rgb(0.74, 0.92, 0.88), dark: rgb(0.13, 0.24, 0.24))
    static let amber = adaptive(light: rgb(0.86, 0.56, 0.22), dark: rgb(0.95, 0.71, 0.35))
    static let rose = adaptive(light: rgb(0.78, 0.31, 0.39), dark: rgb(0.96, 0.49, 0.58))
    static let ink = adaptive(light: rgb(0.10, 0.12, 0.17), dark: rgb(0.93, 0.95, 0.97))
    static let muted = adaptive(light: rgb(0.34, 0.39, 0.46), dark: rgb(0.68, 0.73, 0.79))
    static let mutedSoft = adaptive(light: rgb(0.47, 0.52, 0.58), dark: rgb(0.54, 0.60, 0.66))
    static let canvas = adaptive(light: rgb(0.95, 0.96, 0.94), dark: rgb(0.06, 0.08, 0.10))
    static let panel = adaptive(light: rgba(0.98, 0.985, 0.985, 0.84), dark: rgba(0.11, 0.14, 0.18, 0.88))
    static let panelStrong = adaptive(light: rgba(0.99, 0.995, 0.995, 0.95), dark: rgba(0.14, 0.18, 0.23, 0.96))
    static let hairline = adaptive(light: rgba(0.0, 0.0, 0.0, 0.08), dark: rgba(1.0, 1.0, 1.0, 0.12))
    static let depth = adaptive(light: rgb(0.10, 0.12, 0.17), dark: rgb(0.18, 0.24, 0.30))
    static let backdropStart = adaptive(light: rgb(0.95, 0.96, 0.93), dark: rgb(0.04, 0.06, 0.09))
    static let backdropMid = adaptive(light: rgb(0.90, 0.94, 0.96), dark: rgb(0.06, 0.10, 0.14))
    static let backdropEnd = adaptive(light: rgb(0.97, 0.94, 0.89), dark: rgb(0.08, 0.07, 0.11))

    private static func adaptive(light: NSColor, dark: NSColor) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            switch appearance.bestMatch(from: [.darkAqua, .vibrantDark, .aqua, .vibrantLight]) {
            case .darkAqua, .vibrantDark:
                return dark
            default:
                return light
            }
        })
    }

    private static func rgb(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat) -> NSColor {
        NSColor(srgbRed: red, green: green, blue: blue, alpha: 1)
    }

    private static func rgba(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat, _ alpha: CGFloat) -> NSColor {
        NSColor(srgbRed: red, green: green, blue: blue, alpha: alpha)
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            AppBackdrop()

            Group {
                if model.localVaultLocked {
                    VaultUnlockView()
                } else if model.currentIdentity == nil {
                    OnboardingView()
                } else {
                    WorkspaceView()
                }
            }
            .padding(24)
        }
        .sheet(isPresented: $model.composePresented) {
            ComposeThreadSheet()
                .environmentObject(model)
        }
        .sheet(isPresented: $model.accountCenterPresented) {
            AccountCenterSheet()
                .environmentObject(model)
        }
        .overlay {
            if let message = model.blockingBusyMessage {
                BusyOverlay(message: message)
            }
        }
        .alert("Notrus Mac", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { newValue in
                if !newValue {
                    model.errorMessage = nil
                }
            }
        )) {
            Button("Close", role: .cancel) {
                model.errorMessage = nil
            }
        } message: {
            Text(model.errorMessage ?? "Unknown error")
        }
    }
}

struct AppBackdrop: View {
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    NotrusPalette.backdropStart,
                    NotrusPalette.backdropMid,
                    NotrusPalette.backdropEnd
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            Circle()
                .fill(
                    RadialGradient(
                        colors: [NotrusPalette.accent.opacity(0.32), .clear],
                        center: .center,
                        startRadius: 10,
                        endRadius: 260
                    )
                )
                .frame(width: 520, height: 520)
                .offset(x: -330, y: -220)

            Circle()
                .fill(
                    RadialGradient(
                        colors: [NotrusPalette.amber.opacity(0.24), .clear],
                        center: .center,
                        startRadius: 10,
                        endRadius: 220
                    )
                )
                .frame(width: 440, height: 440)
                .offset(x: 340, y: 250)
        }
    }
}

struct GlassPanel<Content: View>: View {
    let padding: CGFloat
    @ViewBuilder let content: Content

    init(padding: CGFloat = 22, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    var body: some View {
        content
            .padding(padding)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 28, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 28, style: .continuous)
                    .strokeBorder(NotrusPalette.hairline, lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.07), radius: 20, x: 0, y: 8)
    }
}

struct BusyOverlay: View {
    let message: String

    var body: some View {
        ZStack {
            Color.black.opacity(0.12)
                .ignoresSafeArea()

            GlassPanel(padding: 24) {
                HStack(spacing: 14) {
                    ZStack {
                        ProgressView()
                            .controlSize(.large)
                        NotrusLogoMark(size: 34)
                            .scaleEffect(0.58)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Working securely")
                            .font(.system(size: 17, weight: .bold, design: .rounded))
                            .foregroundStyle(NotrusPalette.ink)
                        Text(message)
                            .font(.callout)
                            .foregroundStyle(NotrusPalette.muted)
                            .lineLimit(2)
                    }
                }
            }
            .frame(width: 360)
        }
        .transition(.opacity)
    }
}

struct HeroPill: View {
    let label: String

    var body: some View {
        Text(label.uppercased())
            .font(.system(size: 11, weight: .semibold, design: .rounded))
            .tracking(1.3)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(NotrusPalette.accentSoft, in: Capsule())
            .foregroundStyle(NotrusPalette.ink)
    }
}

struct MetricTile: View {
    let value: String
    let label: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(value)
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
            Text(label)
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .foregroundStyle(NotrusPalette.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

struct OnboardingView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 24) {
                    heroPanel
                    setupPanel
                }
                VStack(spacing: 24) {
                    heroPanel
                    setupPanel
                }
            }
        }
    }

    private var heroPanel: some View {
        GlassPanel(padding: 30) {
            VStack(alignment: .leading, spacing: 22) {
                NotrusBrandLockup(title: "Notrus Mac", subtitle: "Native secure messaging")
                HeroPill(label: "Native Product Vault")

                VStack(alignment: .leading, spacing: 12) {
                    Text("A finished Mac messenger with native key custody, portable recovery, and a relay that only ever sees ciphertext.")
                        .font(.system(size: 42, weight: .bold, design: .rounded))
                        .foregroundStyle(NotrusPalette.ink)
                    Text("Notrus Mac now keeps its profile catalog in a device-authenticated native vault, supports portable recovery archives for deliberate account transfer, and treats new contacts as unverified until you review them.")
                        .font(.system(size: 16, weight: .medium, design: .rounded))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                HStack(spacing: 14) {
                    MetricTile(value: "Vault", label: "Device-protected local storage")
                    MetricTile(value: "E2EE", label: "Ciphertext-only relay path")
                    MetricTile(value: "Mac", label: "Built for a desktop workflow")
                }

                VStack(alignment: .leading, spacing: 14) {
                    SecurityBullet(
                        title: "Portable native profiles",
                        subtitle: "New accounts are created for the Mac app itself, sealed with local device protection, and only exported when you deliberately create an encrypted recovery archive."
                    )
                    SecurityBullet(
                        title: "Direct relay control",
                        subtitle: "The app syncs, creates threads, and sends signed ciphertext without a bridge layer in the middle."
                    )
                    SecurityBullet(
                        title: "Legacy hardware support",
                        subtitle: "Older Secure Enclave-pinned profiles still load locally, while new portable profiles remove the bridge and testing friction."
                    )
                }

                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity)
    }

    private var setupPanel: some View {
        GlassPanel(padding: 28) {
            VStack(alignment: .leading, spacing: 18) {
                Text("Create your native identity")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)

                Text("Start with the relay address, then create the first device-protected Mac profile or import a recovery archive.")
                    .foregroundStyle(.secondary)

                LabeledField(label: "Relay") {
                    TextField("https://relay.example.com or http://127.0.0.1:3000", text: $model.relayOrigin)
                        .textFieldStyle(.roundedBorder)
                        .onChange(of: model.relayOrigin) { _ in
                            model.persistRelayOrigin()
                        }
                }

                LabeledField(label: "Display name") {
                    TextField("Display name", text: $model.onboardingDisplayName)
                        .textFieldStyle(.roundedBorder)
                }

                LabeledField(label: "Username") {
                    TextField("username", text: $model.onboardingUsername)
                        .textFieldStyle(.roundedBorder)
                }

                Button {
                    Task {
                        await model.createIdentity()
                    }
                } label: {
                    HStack {
                        Image(systemName: "lock.shield")
                        Text(model.isBusy ? "Creating profile..." : "Create Native Identity")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(model.isBusy)

                Button {
                    model.accountCenterPresented = true
                } label: {
                    HStack {
                        Image(systemName: "square.and.arrow.down")
                        Text("Import Recovery Archive")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(SecondaryActionButtonStyle())
                .disabled(model.isBusy)

                StatusStrip(text: model.protocolProgramSummary.note, tone: model.protocolBannerTone)
                StatusStrip(text: model.statusMessage, tone: .neutral)

                VStack(alignment: .leading, spacing: 10) {
                    Text("What happens next")
                        .font(.headline)
                    Text("New profiles use a device-authenticated encrypted vault on this Mac. Contacts start unverified, key changes become visible security events, and only explicit recovery archives are moveable.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                Spacer(minLength: 0)
            }
        }
        .frame(maxWidth: 460)
    }
}

struct VaultUnlockView: View {
    @EnvironmentObject private var model: AppModel
    @State private var confirmResetPresented = false

    var body: some View {
        ScrollView {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 24) {
                    unlockHeroPanel
                    unlockActionPanel
                }
                VStack(spacing: 24) {
                    unlockHeroPanel
                    unlockActionPanel
                }
            }
        }
    }

    private var unlockHeroPanel: some View {
        GlassPanel(padding: 30) {
            VStack(alignment: .leading, spacing: 22) {
                NotrusBrandLockup(title: "Notrus Mac", subtitle: "Device-protected local vault")
                HeroPill(label: "Device Unlock")
                Text("Your local Notrus vault is locked.")
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                Text("Unlock with local device authentication to reopen accounts, ratchet state, and contact verification records on this Mac.")
                    .font(.system(size: 16, weight: .medium, design: .rounded))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 14) {
                    MetricTile(value: "Local", label: "Unlock protects app access")
                    MetricTile(value: "This Mac", label: "Vault key is device-only")
                    MetricTile(value: "Review", label: "Security events stay local")
                }

                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity)
    }

    private var unlockActionPanel: some View {
        GlassPanel(padding: 28) {
            VStack(alignment: .leading, spacing: 18) {
                Text("Unlock Notrus Mac")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                Text("This uses Touch ID or macOS device authentication to open the local encrypted vault. It does not verify your contacts or replace message-layer identity.")
                    .foregroundStyle(.secondary)

                Button {
                    Task {
                        await model.unlockLocalVault()
                    }
                } label: {
                    HStack {
                        Image(systemName: "touchid")
                        Text(model.isBusy ? "Unlocking..." : "Unlock Local Vault")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(model.isBusy)

                Button("Reset Local Vault") {
                    confirmResetPresented = true
                }
                .buttonStyle(SecondaryActionButtonStyle())
                .disabled(model.isBusy)

                StatusStrip(text: model.statusMessage, tone: .neutral)
                StatusStrip(
                    text: "Use reset only if this Mac can no longer reopen the old local vault. Reset clears local accounts, thread state, and contact verification data from this machine.",
                    tone: .warning
                )
                Spacer(minLength: 0)
            }
        }
        .frame(maxWidth: 460)
        .alert("Reset Local Vault?", isPresented: $confirmResetPresented) {
            Button("Cancel", role: .cancel) {}
            Button("Reset", role: .destructive) {
                Task {
                    await model.resetLocalVault()
                }
            }
        } message: {
            Text("This deletes the local Notrus vault, cached thread state, and contact verification records on this Mac. Use it only if the old vault cannot be reopened and you plan to import a recovery archive or start fresh.")
        }
    }
}

struct SecurityBullet: View {
    let title: String
    let subtitle: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Circle()
                .fill(NotrusPalette.accent)
                .frame(width: 10, height: 10)
                .padding(.top, 7)

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 16, weight: .semibold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                Text(subtitle)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct LabeledField<Content: View>: View {
    let label: String
    @ViewBuilder let content: Content

    init(label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label)
                .font(.system(size: 12, weight: .semibold, design: .rounded))
                .foregroundStyle(.secondary)
            content
        }
    }
}

struct WorkspaceView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationSplitView {
            sidebar
        } content: {
            threadList
        } detail: {
            detailPane
        }
        .navigationSplitViewStyle(.balanced)
        .toolbar {
            ToolbarItemGroup {
                Button("Sync") {
                    Task {
                        await model.syncNow()
                    }
                }
                Button("Lock") {
                    model.lockLocalVault()
                }
                Button("New Thread") {
                    model.presentComposer()
                }
                Button("Account Center") {
                    model.accountCenterPresented = true
                }
            }
        }
    }

    private var sidebar: some View {
        GlassPanel {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let identity = model.currentIdentity {
                        SidebarIdentityCard(
                            identity: identity,
                            contactsCount: model.visibleContactRecords.count,
                            threadsCount: model.threads.count
                        )
                    }

                    ProfileSwitcherCard(
                        profiles: model.localProfiles,
                        currentProfileId: model.currentIdentity?.id,
                        isBusy: model.isBusy,
                        openAccountCenter: {
                            model.accountCenterPresented = true
                        },
                        switchProfile: { profileId in
                            Task {
                                await model.switchIdentity(to: profileId)
                            }
                        }
                    )

                    LabeledField(label: "Relay URL") {
                        TextField("Relay URL", text: $model.relayOrigin)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: model.relayOrigin) { _ in
                                model.persistRelayOrigin()
                            }
                    }

                    StatusStrip(
                        text: TransportSecurityPolicy.isLocalDevelopmentOrigin(model.relayOrigin)
                            ? "Localhost HTTP is allowed only for same-Mac development. Remote relays must use HTTPS."
                            : "Remote relays are required to use HTTPS with ATS-protected transport.",
                        tone: .neutral
                    )

                    LabeledField(label: "Witness Origins") {
                        TextField("http://127.0.0.1:3400, https://witness.example", text: $model.witnessOriginsText, axis: .vertical)
                            .lineLimit(1...3)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: model.witnessOriginsText) { _ in
                                model.persistWitnessOrigins()
                            }
                    }

                    StatusStrip(text: model.protocolProgramSummary.note, tone: model.protocolBannerTone)
                    SecurityCenterCard()
                    TransparencyCard(
                        transparency: model.transparency,
                        onResetTrust: model.transparency.chainValid ? nil : {
                            Task {
                                await model.resetTransparencyTrust()
                            }
                        }
                    )
                    StatusStrip(text: model.statusMessage, tone: .neutral)
                    Spacer(minLength: 0)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .scrollIndicators(.never)
        }
        .padding(.trailing, 8)
        .frame(minWidth: 310)
    }

    private var threadList: some View {
        GlassPanel(padding: 16) {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Threads")
                            .font(.system(size: 24, weight: .bold, design: .rounded))
                            .foregroundStyle(NotrusPalette.ink)
                        Text("\(model.threads.count) conversations synced from the relay")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("New Thread") {
                        model.presentComposer()
                    }
                    .buttonStyle(SecondaryActionButtonStyle())
                }

                if model.threads.isEmpty {
                    ThreadEmptyState()
                } else {
                    ScrollView {
                        VStack(spacing: 12) {
                            ForEach(model.threads) { thread in
                                ThreadRow(
                                    thread: thread,
                                    isSelected: model.selectedThreadID == thread.id
                                )
                                .onTapGesture {
                                    model.selectedThreadID = thread.id
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private var detailPane: some View {
        GlassPanel {
            Group {
                if let thread = model.selectedThread {
                    ConversationView(thread: thread)
                } else {
                    EmptyDetailPane()
                }
            }
        }
    }
}

struct SidebarIdentityCard: View {
    let identity: LocalIdentity
    let contactsCount: Int
    let threadsCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 14) {
                    identityAvatar
                    identityText
                    Spacer(minLength: 0)
                }
                VStack(alignment: .leading, spacing: 14) {
                    identityAvatar
                    identityText
                }
            }

            HStack(spacing: 10) {
                MiniStat(label: "Contacts", value: "\(contactsCount)")
                MiniStat(label: "Threads", value: "\(threadsCount)")
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Fingerprint")
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
                Text(identity.fingerprint)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .foregroundStyle(NotrusPalette.ink)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
            .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
    }

    private var identityAvatar: some View {
        NotrusLogoMark(size: 54)
    }

    private var identityText: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(identity.displayName)
                .font(.system(size: 24, weight: .bold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            Text("@\(identity.username)")
                .foregroundStyle(.secondary)
                .lineLimit(1)
            StorageBadge(storageMode: identity.storageMode)
        }
    }
}

struct MiniStat: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.system(size: 18, weight: .bold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Text(label)
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

struct StorageBadge: View {
    let storageMode: String?

    var body: some View {
        Text(label)
            .font(.system(size: 10, weight: .semibold, design: .rounded))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(backgroundColor, in: Capsule())
            .foregroundStyle(foregroundColor)
            .lineLimit(1)
    }

    private var label: String {
        switch storageMode {
        case "secure-enclave-v1":
            return "Legacy Hardware"
        case "device-vault-v2":
            return "Device Vault"
        default:
            return "Recovery Import"
        }
    }

    private var backgroundColor: Color {
        switch storageMode {
        case "secure-enclave-v1":
            return NotrusPalette.amber.opacity(0.18)
        case "device-vault-v2":
            return NotrusPalette.accentSoft
        default:
            return NotrusPalette.panel
        }
    }

    private var foregroundColor: Color {
        switch storageMode {
        case "secure-enclave-v1":
            return NotrusPalette.amber
        case "device-vault-v2":
            return NotrusPalette.ink
        default:
            return .secondary
        }
    }
}

struct ProfileSwitcherCard: View {
    let profiles: [LocalIdentity]
    let currentProfileId: String?
    let isBusy: Bool
    let openAccountCenter: () -> Void
    let switchProfile: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Local Profiles")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                Spacer()
                Button("Manage") {
                    openAccountCenter()
                }
                .buttonStyle(.plain)
                .foregroundStyle(NotrusPalette.accent)
            }

            if profiles.isEmpty {
                Text("Create or import the first Mac profile to begin.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                VStack(spacing: 10) {
                    ForEach(profiles, id: \.id) { profile in
                        Button {
                            guard profile.id != currentProfileId else {
                                openAccountCenter()
                                return
                            }
                            switchProfile(profile.id)
                        } label: {
                            ViewThatFits(in: .horizontal) {
                                HStack(alignment: .center, spacing: 12) {
                                    profileIndicator(isActive: profile.id == currentProfileId)
                                    profileSummary(profile)
                                    Spacer(minLength: 8)
                                    StorageBadge(storageMode: profile.storageMode)
                                }
                                VStack(alignment: .leading, spacing: 10) {
                                    HStack(alignment: .center, spacing: 12) {
                                        profileIndicator(isActive: profile.id == currentProfileId)
                                        profileSummary(profile)
                                    }
                                    StorageBadge(storageMode: profile.storageMode)
                                }
                            }
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                RoundedRectangle(cornerRadius: 16, style: .continuous)
                                    .fill(profile.id == currentProfileId ? NotrusPalette.accentSoft.opacity(0.92) : NotrusPalette.panelStrong)
                            )
                        }
                        .buttonStyle(.plain)
                        .disabled(isBusy)
                    }
                }
            }
        }
        .padding(16)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private func profileIndicator(isActive: Bool) -> some View {
        Circle()
            .fill(isActive ? NotrusPalette.accent : NotrusPalette.panel)
            .frame(width: 12, height: 12)
    }

    private func profileSummary(_ profile: LocalIdentity) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(profile.displayName)
                .font(.system(size: 14, weight: .semibold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
                .lineLimit(2)
            Text("@\(profile.username)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
    }
}

struct SecurityCenterCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Security Review")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                Spacer()
                Text(model.hasPendingSecurityActions ? "Action needed" : "Up to date")
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(
                        model.hasPendingSecurityActions ? NotrusPalette.amber.opacity(0.18) : NotrusPalette.accentSoft,
                        in: Capsule()
                    )
                    .foregroundStyle(model.hasPendingSecurityActions ? NotrusPalette.amber : NotrusPalette.ink)
            }

            Text(
                model.activeSecurityEvents.first?.message ??
                "New contacts begin unverified, and any identity-key change becomes a visible security event on this Mac."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 10) {
                    MiniStat(
                        label: "Pending",
                        value: "\(model.activeSecurityEvents.filter { $0.dismissedAt == nil }.count)"
                    )
                    MiniStat(
                        label: "Verified",
                        value: "\(model.visibleContactRecords.filter { $0.status == .verified }.count)"
                    )
                }
                VStack(spacing: 10) {
                    MiniStat(
                        label: "Pending",
                        value: "\(model.activeSecurityEvents.filter { $0.dismissedAt == nil }.count)"
                    )
                    MiniStat(
                        label: "Verified",
                        value: "\(model.visibleContactRecords.filter { $0.status == .verified }.count)"
                    )
                }
            }

            if let event = model.activeSecurityEvents.first {
                SecurityEventRow(event: event, compact: true)
            }
        }
        .padding(16)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

struct TrustBadge: View {
    let status: ContactTrustStatus?

    var body: some View {
        Text(label)
            .font(.system(size: 10, weight: .semibold, design: .rounded))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(background, in: Capsule())
            .foregroundStyle(foreground)
    }

    private var label: String {
        switch status {
        case .verified:
            return "Verified"
        case .changed:
            return "Changed"
        default:
            return "Unverified"
        }
    }

    private var background: Color {
        switch status {
        case .verified:
            return NotrusPalette.accentSoft
        case .changed:
            return NotrusPalette.rose.opacity(0.18)
        default:
            return NotrusPalette.amber.opacity(0.18)
        }
    }

    private var foreground: Color {
        switch status {
        case .verified:
            return NotrusPalette.ink
        case .changed:
            return NotrusPalette.rose
        default:
            return NotrusPalette.amber
        }
    }
}

struct SecurityEventRow: View {
    let event: ContactSecurityEvent
    let compact: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(event.displayName)
                    .font(.system(size: 14, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                Spacer()
                Text(event.requiresAction ? "Review" : "Info")
                    .font(.system(size: 10, weight: .semibold, design: .rounded))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background((event.requiresAction ? NotrusPalette.amber.opacity(0.18) : NotrusPalette.accentSoft), in: Capsule())
                    .foregroundStyle(event.requiresAction ? NotrusPalette.amber : NotrusPalette.ink)
            }

            Text(event.message)
                .font(compact ? .caption : .callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

struct ThreadEmptyState: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HeroPill(label: "Quiet relay")
            Text("No threads yet")
                .font(.system(size: 30, weight: .bold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
            Text("Create the first native conversation after another identity registers with the relay. The Mac client will establish the correct local session state for the selected protocol and keep the private side on this Mac.")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 220, alignment: .leading)
        .padding(24)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }
}

struct EmptyDetailPane: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HeroPill(label: "Select a thread")
            Text("Choose a conversation or create a new one.")
                .font(.system(size: 30, weight: .bold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
            Text("The detail pane becomes your native encrypted workspace once a thread is active.")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

struct ThreadRow: View {
    let thread: ConversationThread
    let isSelected: Bool

    private var participantsLine: String {
        thread.participants.map(\.displayName).joined(separator: ", ")
    }

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(isSelected ? NotrusPalette.accent : NotrusPalette.panelStrong)
                Image(systemName: thread.supported ? "ellipsis.message.fill" : "exclamationmark.shield")
                    .foregroundStyle(isSelected ? .white : (thread.supported ? NotrusPalette.ink : NotrusPalette.amber))
            }
            .frame(width: 44, height: 44)

            VStack(alignment: .leading, spacing: 6) {
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 10) {
                        Text(verbatim: thread.title)
                            .font(.system(size: 16, weight: .bold, design: .rounded))
                            .foregroundStyle(isSelected ? .white : NotrusPalette.ink)
                            .lineLimit(2)
                        Spacer(minLength: 0)
                        ProtocolBadge(label: thread.protocolLabel, supported: thread.supported, inverted: isSelected)
                    }
                    VStack(alignment: .leading, spacing: 8) {
                        Text(verbatim: thread.title)
                            .font(.system(size: 16, weight: .bold, design: .rounded))
                            .foregroundStyle(isSelected ? .white : NotrusPalette.ink)
                            .lineLimit(2)
                        ProtocolBadge(label: thread.protocolLabel, supported: thread.supported, inverted: isSelected)
                    }
                }

                Text(participantsLine)
                    .font(.callout)
                    .foregroundStyle(isSelected ? Color.white.opacity(0.86) : NotrusPalette.muted)
                    .lineLimit(2)

                if let warning = thread.warning {
                    Text(warning)
                        .font(.caption)
                        .foregroundStyle(isSelected ? Color.white.opacity(0.8) : NotrusPalette.amber)
                        .lineLimit(2)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .fill(isSelected ? NotrusPalette.depth : NotrusPalette.panelStrong)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .strokeBorder(isSelected ? Color.clear : NotrusPalette.hairline, lineWidth: 1)
        )
        .shadow(color: .black.opacity(isSelected ? 0.14 : 0.04), radius: isSelected ? 16 : 8, x: 0, y: 8)
    }
}

struct ProtocolBadge: View {
    let label: String
    let supported: Bool
    let inverted: Bool

    var body: some View {
        Text(label)
            .font(.system(size: 11, weight: .semibold, design: .rounded))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(backgroundColor, in: Capsule())
            .foregroundStyle(foregroundColor)
    }

    private var backgroundColor: Color {
        if inverted {
            return Color.white.opacity(0.14)
        }
        return supported ? NotrusPalette.accentSoft : NotrusPalette.amber.opacity(0.18)
    }

    private var foregroundColor: Color {
        if inverted {
            return .white
        }
        return supported ? NotrusPalette.ink : NotrusPalette.amber
    }
}

struct ConversationView: View {
    @EnvironmentObject private var model: AppModel
    let thread: ConversationThread

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ConversationHeader(thread: thread)

            if let warning = thread.warning {
                StatusStrip(text: warning, tone: .warning)
            }

            if model.selectedThreadRequiresReverification {
                StatusStrip(
                    text: "A contact in this conversation changed identity keys. Verify the new safety number in Account Center before sending more content.",
                    tone: .warning
                )
            }

            if model.selectedThreadContainsBlockedContact {
                StatusStrip(
                    text: "A blocked contact is part of this conversation on this Mac. Sending stays disabled until you unblock them.",
                    tone: .warning
                )
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(thread.messages) { message in
                        MessageBubble(
                            message: message,
                            isCurrentUser: message.senderId == model.currentIdentity?.id,
                            saveAttachment: { reference in
                                Task {
                                    await model.saveAttachment(reference, in: thread)
                                }
                            }
                        )
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            ComposerBar(
                text: $model.draftText,
                pendingAttachments: model.pendingAttachments,
                isBusy: model.isBusy,
                canSend: model.canSendMessage,
                supported: thread.supported,
                chooseAttachments: {
                    Task {
                        await model.chooseAttachments()
                    }
                },
                removeAttachment: { attachmentId in
                    model.removePendingAttachment(attachmentId)
                }
            ) {
                Task {
                    await model.sendMessage()
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

struct ConversationHeader: View {
    @EnvironmentObject private var model: AppModel
    let thread: ConversationThread

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top) {
                    titleBlock
                    Spacer()
                    ProtocolBadge(label: thread.protocolLabel, supported: thread.supported, inverted: false)
                }
                VStack(alignment: .leading, spacing: 10) {
                    titleBlock
                    ProtocolBadge(label: thread.protocolLabel, supported: thread.supported, inverted: false)
                }
            }

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 10) {
                    headerChips
                }
                VStack(alignment: .leading, spacing: 10) {
                    headerChips
                }
            }

            HStack(spacing: 10) {
                Button("Delete Local Conversation", role: .destructive) {
                    model.deleteConversationLocally(thread.id)
                }
                .buttonStyle(SecondaryActionButtonStyle())
                .disabled(model.isBusy)
            }
        }
    }

    private var titleBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(thread.title)
                .font(.system(size: 30, weight: .bold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            Text(thread.participants.map(\.displayName).joined(separator: ", "))
                .foregroundStyle(NotrusPalette.muted)
                .lineLimit(2)
        }
    }

    @ViewBuilder
    private var headerChips: some View {
        MetadataChip(label: "\(thread.participants.count) people")
        MetadataChip(label: thread.messages.isEmpty ? "Empty" : "\(thread.messages.count) msgs")
        MetadataChip(label: thread.supported ? "Decrypt on" : "Metadata only")
        if let remoteParticipant = thread.participants.first(where: { $0.id != model.currentIdentity?.id }) {
            TrustBadge(status: model.contactTrust(for: remoteParticipant.id)?.status)
            if model.isContactBlocked(remoteParticipant.id) {
                MetadataChip(label: "Blocked")
            }
        }
    }
}

struct MetadataChip: View {
    let label: String

    var body: some View {
        Text(label)
            .font(.system(size: 12, weight: .medium, design: .rounded))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(NotrusPalette.panelStrong, in: Capsule())
            .foregroundStyle(NotrusPalette.muted)
    }
}

struct MessageBubble: View {
    let message: DecryptedMessage
    let isCurrentUser: Bool
    let saveAttachment: (SecureAttachmentReference) -> Void

    var body: some View {
        HStack {
            if isCurrentUser {
                Spacer(minLength: 90)
            }

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(message.senderName)
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                    Spacer(minLength: 10)
                    Text(shortTimestamp(message.createdAt))
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .opacity(0.72)
                }

                Text(message.body)
                    .font(.system(size: 15, weight: .medium, design: .rounded))
                    .fixedSize(horizontal: false, vertical: true)

                if !message.attachments.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(message.attachments) { attachment in
                            Button {
                                saveAttachment(attachment)
                            } label: {
                                HStack(spacing: 10) {
                                    Image(systemName: "paperclip.circle.fill")
                                        .font(.system(size: 18, weight: .semibold))
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(attachment.fileName)
                                            .font(.system(size: 13, weight: .semibold, design: .rounded))
                                            .lineLimit(1)
                                        Text("\(attachment.mediaType) • \(formattedByteCount(attachment.byteLength))")
                                            .font(.system(size: 11, weight: .medium, design: .rounded))
                                            .opacity(0.75)
                                            .lineLimit(1)
                                    }
                                    Spacer(minLength: 8)
                                    Text("Save")
                                        .font(.system(size: 11, weight: .bold, design: .rounded))
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 10)
                                .background(
                                    Color.white.opacity(isCurrentUser ? 0.10 : 0.55),
                                    in: RoundedRectangle(cornerRadius: 16, style: .continuous)
                                )
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.top, 2)
                }
            }
            .foregroundStyle(bubbleForeground)
            .padding(16)
            .background(bubbleBackground, in: RoundedRectangle(cornerRadius: 22, style: .continuous))

            if !isCurrentUser {
                Spacer(minLength: 90)
            }
        }
    }

    private var bubbleForeground: Color {
        if message.status != "ok" {
            return NotrusPalette.ink
        }
        return isCurrentUser ? .white : NotrusPalette.ink
    }

    private var bubbleBackground: Color {
        if message.status != "ok" {
            return NotrusPalette.amber.opacity(0.22)
        }
        return isCurrentUser ? NotrusPalette.depth : NotrusPalette.panelStrong
    }
}

struct ComposerBar: View {
    @Binding var text: String
    let pendingAttachments: [LocalAttachmentDraft]
    let isBusy: Bool
    let canSend: Bool
    let supported: Bool
    let chooseAttachments: () -> Void
    let removeAttachment: (String) -> Void
    let send: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(supported ? "Message composer" : "Protocol unavailable in native client")
                .font(.system(size: 12, weight: .semibold, design: .rounded))
                .foregroundStyle(.secondary)

            if !pendingAttachments.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ForEach(pendingAttachments) { attachment in
                            HStack(spacing: 8) {
                                Image(systemName: "paperclip")
                                    .foregroundStyle(NotrusPalette.accent)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(attachment.fileName)
                                        .font(.system(size: 12, weight: .semibold, design: .rounded))
                                        .lineLimit(1)
                                    Text(formattedByteCount(attachment.byteLength))
                                        .font(.system(size: 10, weight: .medium, design: .rounded))
                                        .foregroundStyle(.secondary)
                                }
                                Button {
                                    removeAttachment(attachment.id)
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 9)
                            .background(NotrusPalette.canvas.opacity(0.92), in: Capsule())
                        }
                    }
                    .padding(.vertical, 2)
                }
            }

            HStack(alignment: .bottom, spacing: 12) {
                Button {
                    chooseAttachments()
                } label: {
                    Image(systemName: "paperclip.circle.fill")
                        .font(.system(size: 21, weight: .semibold))
                }
                .buttonStyle(.plain)
                .foregroundStyle(supported && !isBusy ? NotrusPalette.ink : .secondary)
                .disabled(!supported || isBusy)

                TextField(
                    supported ? "Write a message. The relay only sees ciphertext." : "Unsupported protocol in native Mac client",
                    text: $text,
                    axis: .vertical
                )
                .lineLimit(1...5)
                .textFieldStyle(.roundedBorder)
                .disabled(!supported || isBusy)

                Button {
                    send()
                } label: {
                    HStack {
                        Image(systemName: "paperplane.fill")
                        Text(isBusy ? "Sending..." : "Send")
                    }
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(!canSend || isBusy)
            }
        }
        .padding(16)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }
}

struct StatusStrip: View {
    enum Tone {
        case neutral
        case warning
    }

    let text: String
    let tone: Tone

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: tone == .warning ? "exclamationmark.triangle.fill" : "checkmark.shield")
            Text(text)
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .lineLimit(3)
        }
        .foregroundStyle(foreground)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(background, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private var foreground: Color {
        tone == .warning ? NotrusPalette.amber : NotrusPalette.ink
    }

    private var background: Color {
        tone == .warning ? NotrusPalette.amber.opacity(0.18) : NotrusPalette.accentSoft.opacity(0.8)
    }
}

struct TransparencyCard: View {
    let transparency: TransparencyVerificationResult
    let onResetTrust: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Transparency")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                Spacer()
                Text(transparency.chainValid ? "Verified" : "Check")
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(
                        transparency.chainValid ? NotrusPalette.accentSoft : NotrusPalette.amber.opacity(0.18),
                        in: Capsule()
                    )
                    .foregroundStyle(transparency.chainValid ? NotrusPalette.ink : NotrusPalette.amber)
            }

            Text(
                transparency.chainValid
                    ? "The relay identity history and this Mac's pinned head are consistent."
                    : (transparency.warnings.first ?? "Transparency verification requires attention.")
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                MiniStat(label: "Entries", value: "\(transparency.entries.count)")
                MiniStat(label: "Witnesses", value: "\(transparency.witnesses.count)")
            }

            if let head = transparency.head {
                MetadataChip(label: "Head \(String(head.prefix(16)))...")
            }

            if let pinned = transparency.pinnedHead {
                MetadataChip(label: "Pinned \(String(pinned.prefix(16)))...")
            }

            if !transparency.witnesses.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(transparency.witnesses) { witness in
                        WitnessRow(witness: witness)
                    }
                }
            }

            if let onResetTrust, !transparency.chainValid {
                Button("Reset Transparency Trust") {
                    onResetTrust()
                }
                .buttonStyle(.borderedProminent)
                .tint(NotrusPalette.amber)
            }
        }
        .padding(16)
        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

struct WitnessRow: View {
    let witness: WitnessObservation

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(witness.origin)
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .foregroundStyle(NotrusPalette.ink)
                    .lineLimit(1)
                Text(witness.head.map { "Head \(String($0.prefix(12)))..." } ?? "No head observed yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text(witness.status.capitalized)
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(witnessStatusColor.opacity(0.14), in: Capsule())
                .foregroundStyle(witnessStatusColor)
        }
    }

    private var witnessStatusColor: Color {
        switch witness.status {
        case "current":
            return NotrusPalette.accent
        case "lagging":
            return NotrusPalette.amber
        case "conflict":
            return NotrusPalette.rose
        default:
            return .secondary
        }
    }
}

struct ComposeThreadSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            AppBackdrop()

            GlassPanel(padding: 24) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        Text("Create Native Thread")
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .foregroundStyle(NotrusPalette.ink)
                        Text("Pick one or more relay contacts. Notrus Mac will create the right local state for the selected protocol and keep decrypted session state on this Mac.")
                            .foregroundStyle(.secondary)

                        LabeledField(label: "Optional local title") {
                            TextField("Stored only on this Mac", text: $model.composeTitle)
                                .textFieldStyle(.roundedBorder)
                        }

                        Text("Participants")
                            .font(.system(size: 14, weight: .semibold, design: .rounded))
                            .foregroundStyle(.secondary)

                        ViewThatFits(in: .horizontal) {
                            HStack(spacing: 12) {
                                searchField
                                searchButton
                            }
                            VStack(spacing: 12) {
                                searchField
                                searchButton
                            }
                        }

                        Text(
                            model.currentUser?.directoryCode.map { "Your invite code is \($0). Notrus sync stays scoped to your existing contacts and threads; use username or invite-code lookup when you want to discover a new contact." }
                                ?? "Notrus sync now stays scoped to your existing contacts and threads. Use username or invite-code lookup when you want to discover a new contact."
                        )
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        VStack(alignment: .leading, spacing: 8) {
                            Text(model.composeProtocolPreview)
                                .font(.system(size: 17, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)
                            Text(model.composeProtocolNote)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                            if let warning = model.composeSelectionWarning {
                                Text(warning)
                                    .font(.caption)
                                    .foregroundStyle(NotrusPalette.amber)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 18, style: .continuous))

                        VStack(spacing: 10) {
                            ForEach(model.composeCandidates) { contact in
                                ContactSelectionRow(
                                    contact: contact,
                                    isSelected: model.composeSelection.contains(contact.id),
                                    trust: model.contactTrust(for: contact.id)
                                ) { enabled in
                                    if enabled {
                                        model.composeSelection.insert(contact.id)
                                    } else {
                                        model.composeSelection.remove(contact.id)
                                    }
                                }
                            }
                        }

                        HStack {
                            Button("Cancel") {
                                dismiss()
                            }
                            .buttonStyle(SecondaryActionButtonStyle())

                            Spacer()

                            Button(model.isBusy ? "Creating..." : "Create Thread") {
                                Task {
                                    await model.createThread()
                                    if model.errorMessage == nil {
                                        dismiss()
                                    }
                                }
                            }
                            .buttonStyle(PrimaryActionButtonStyle())
                            .disabled(model.isBusy || !model.canCreateComposedThread)
                        }
                    }
                }
            }
        }
        .frame(minWidth: 420, idealWidth: 760, minHeight: 560)
        .padding(28)
    }

    private var searchField: some View {
        TextField("Lookup by invite code or username", text: $model.directorySearchQuery)
            .textFieldStyle(.roundedBorder)
            .onSubmit {
                Task {
                    await model.searchDirectory()
                }
            }
    }

    private var searchButton: some View {
        Button("Search") {
            Task {
                await model.searchDirectory()
            }
        }
        .buttonStyle(SecondaryActionButtonStyle())
        .disabled(model.directorySearchQuery.trimmingCharacters(in: .whitespacesAndNewlines).count < 3 || model.isBusy)
    }
}

private struct AdaptiveFieldRow<Leading: View, Trailing: View>: View {
    @ViewBuilder let leading: Leading
    @ViewBuilder let trailing: Trailing

    init(@ViewBuilder leading: () -> Leading, @ViewBuilder trailing: () -> Trailing) {
        self.leading = leading()
        self.trailing = trailing()
    }

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 14) {
                leading
                trailing
            }
            VStack(spacing: 14) {
                leading
                trailing
            }
        }
    }
}

struct ContactSelectionRow: View {
    let contact: RelayUser
    let isSelected: Bool
    let trust: ContactTrustRecord?
    let toggle: (Bool) -> Void

    var body: some View {
        Toggle(
            isOn: Binding(
                get: { isSelected },
                set: toggle
            )
        ) {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(contact.displayName)
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundStyle(NotrusPalette.ink)
                    TrustBadge(status: trust?.status)
                    if contact.mlsKeyPackage == nil {
                        MetadataChip(label: "Direct only")
                    }
                }
                Text("@\(contact.username)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(
                    trust?.blockedAt != nil
                        ? "This contact is blocked on this Mac and will not appear in the new-thread composer until you unblock them."
                        : trust?.status == .changed
                        ? "This contact changed identity keys and must be reviewed before you trust the new key."
                        : "Review the safety number in Account Center before trusting this contact for high-risk content."
                )
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
        }
        .toggleStyle(.checkbox)
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(isSelected ? NotrusPalette.accentSoft.opacity(0.9) : NotrusPalette.panelStrong)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(isSelected ? NotrusPalette.accent.opacity(0.4) : NotrusPalette.hairline, lineWidth: 1)
        )
    }
}

struct AccountCenterSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @AppStorage("NotrusMac.appearanceMode") private var appearanceModeRaw = AppAppearanceMode.system.rawValue
    @State private var exportPassphrase = ""
    @State private var importPassphrase = ""
    @State private var preparedExport: PreparedRecoveryArchiveExport?
    @State private var exportPickerPresented = false
    @State private var importPickerPresented = false

    var body: some View {
        ZStack {
            AppBackdrop()

            GlassPanel(padding: 26) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Account Center")
                                    .font(.system(size: 30, weight: .bold, design: .rounded))
                                    .foregroundStyle(NotrusPalette.ink)
                                Text("Manage local profiles, switch test identities, and move portable accounts with encrypted recovery archives.")
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Close") {
                                dismiss()
                            }
                            .buttonStyle(SecondaryActionButtonStyle())
                        }

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Appearance")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            Text("Choose whether Notrus Mac follows the system appearance or stays in a dedicated light or dark presentation.")
                                .font(.callout)
                                .foregroundStyle(.secondary)

                            Picker("Appearance", selection: $appearanceModeRaw) {
                                ForEach(AppAppearanceMode.allCases) { mode in
                                    Text(mode.title).tag(mode.rawValue)
                                }
                            }
                            .pickerStyle(.segmented)
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Privacy Mode")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            Text("When enabled, Notrus adds short random delays before routine relay sync, directory lookup, thread creation, and message delivery. This weakens timing correlation at the cost of responsiveness.")
                                .font(.callout)
                                .foregroundStyle(.secondary)

                            Toggle(isOn: Binding(
                                get: { model.privacyModeEnabled },
                                set: { enabled in
                                    model.privacyModeEnabled = enabled
                                    model.persistPrivacyMode()
                                }
                            )) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Reduce timing correlation")
                                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                                        .foregroundStyle(NotrusPalette.ink)
                                    Text(model.privacyModeEnabled ? "Adds a small randomized delay to routine network actions, usually about 0.1 to 0.9 seconds depending on the action." : "Uses the fastest routine relay behavior.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .toggleStyle(.switch)
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Stored on This Mac")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            Text("Inspect the local vault backend, current device key state, and every profile stored on this Mac before creating or importing another account.")
                                .font(.callout)
                                .foregroundStyle(.secondary)

                            HStack(spacing: 10) {
                                MetadataChip(label: model.localDeviceInventory.vaultStorageMode)
                                MetadataChip(label: model.localDeviceInventory.vaultKeyPresent ? "Vault key present" : "Vault key missing")
                                MetadataChip(label: "\(model.localDeviceInventory.profileCount) profiles")
                            }

                            if let appInstanceId = model.localDeviceInventory.appInstanceId {
                                inventoryRow(label: "App instance", value: appInstanceId, trailing: nil)
                            }

                            if let deviceId = model.localDeviceInventory.deviceId {
                                inventoryRow(
                                    label: "Device ID",
                                    value: deviceId,
                                    trailing: model.localDeviceInventory.deviceKeyStorageMode
                                )
                            }

                            inventoryRow(
                                label: "Metadata store",
                                value: model.localDeviceInventory.metadataDirectoryLabel,
                                trailing: model.localDeviceInventory.vaultStorageMode
                            )

                            if model.localDeviceInventory.profiles.isEmpty {
                                Text("No local profiles are currently stored on this Mac.")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            } else {
                                ForEach(model.localDeviceInventory.profiles, id: \.id) { profile in
                                    VStack(alignment: .leading, spacing: 8) {
                                        Text(profile.displayName)
                                            .font(.system(size: 15, weight: .semibold, design: .rounded))
                                            .foregroundStyle(NotrusPalette.ink)
                                        Text("@\(profile.username)")
                                            .font(.callout)
                                            .foregroundStyle(.secondary)
                                        HStack(spacing: 8) {
                                            StorageBadge(storageMode: profile.storageMode)
                                            if let directoryCode = profile.directoryCode {
                                                MetadataChip(label: "Invite \(directoryCode)")
                                            }
                                        }
                                        Text(profile.id)
                                            .font(.system(size: 12, weight: .medium, design: .monospaced))
                                            .foregroundStyle(NotrusPalette.muted)
                                            .textSelection(.enabled)
                                    }
                                    .padding(14)
                                    .background(NotrusPalette.panelStrong.opacity(0.75), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                                }
                            }
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                        VStack(alignment: .leading, spacing: 12) {
                            Text("Profiles on This Mac")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            ForEach(model.localProfiles, id: \.id) { profile in
                                ViewThatFits(in: .horizontal) {
                                    HStack(alignment: .center, spacing: 14) {
                                        profileIdentitySummary(profile)
                                        Spacer()
                                        profileTrailingActions(profile)
                                    }

                                    VStack(alignment: .leading, spacing: 12) {
                                        profileIdentitySummary(profile)
                                        profileTrailingActions(profile)
                                    }
                                }
                                .padding(16)
                                .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                            }

                            if model.currentIdentity != nil {
                                HStack(spacing: 12) {
                                    Button("Rotate Active Identity Keys") {
                                        Task {
                                            await model.rotateCurrentIdentityKeys()
                                        }
                                    }
                                    .buttonStyle(SecondaryActionButtonStyle())

                                    Button("Delete Active Profile", role: .destructive) {
                                        Task {
                                            await model.deleteCurrentIdentity()
                                            if !model.hasProfiles {
                                                dismiss()
                                            }
                                        }
                                    }
                                    .buttonStyle(SecondaryActionButtonStyle())
                                }
                            }
                        }

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Device Integrity")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            if let integrity = model.integrityReport {
                                HStack(spacing: 10) {
                                    MetadataChip(label: "Risk \(integrity.riskLevel.capitalized)")
                                    MetadataChip(label: "Code \(integrity.codeSignatureStatus)")
                                    MetadataChip(label: "DeviceCheck \(integrity.deviceCheckStatus)")
                                }

                                if let directoryCode = model.currentUser?.directoryCode {
                                    Text("Invite code: \(directoryCode)")
                                        .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                        .foregroundStyle(NotrusPalette.accent)
                                }

                                Text("macOS does not support App Attest for native Mac apps, so Notrus Mac uses local code-signature validation plus DeviceCheck token availability as a coarse risk signal. This does not replace end-to-end cryptography.")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)

                                if let note = integrity.note, !note.isEmpty {
                                    Text(note)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            } else {
                                Text("Collecting local code-signature and DeviceCheck status for this app instance.")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Linked Devices")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            Text("Each linked device keeps its own device-management key. Add and revoke events are visible here and stay separate from conversation membership.")
                                .font(.callout)
                                .foregroundStyle(.secondary)

                            if model.linkedDevices.isEmpty {
                                Text("No linked devices are registered for this account yet.")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            } else {
                                VStack(spacing: 12) {
                                    ForEach(model.linkedDevices, id: \.id) { device in
                                        HStack(alignment: .top, spacing: 12) {
                                            VStack(alignment: .leading, spacing: 4) {
                                                HStack(spacing: 8) {
                                                    Text(device.label)
                                                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                                                        .foregroundStyle(NotrusPalette.ink)
                                                    if device.current {
                                                        MetadataChip(label: "This Mac")
                                                    }
                                                    if device.revokedAt != nil {
                                                        MetadataChip(label: "Revoked")
                                                    }
                                                }
                                                Text("\(device.platform) · \(device.id)")
                                                    .font(.caption)
                                                    .foregroundStyle(.secondary)
                                                    .textSelection(.enabled)
                                                Text("Risk \(device.riskLevel.capitalized) · Updated \(relativeDate(device.updatedAt))")
                                                    .font(.caption2)
                                                    .foregroundStyle(.secondary)
                                            }

                                            Spacer()
                                            if !device.current && device.revokedAt == nil {
                                                Button("Revoke", role: .destructive) {
                                                    Task {
                                                        await model.revokeLinkedDevice(device.id)
                                                    }
                                                }
                                                .buttonStyle(SecondaryActionButtonStyle())
                                                .disabled(model.isBusy)
                                            }
                                        }
                                        .padding(14)
                                        .background(NotrusPalette.panelStrong.opacity(0.75), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                                    }
                                }
                            }

                            if !model.linkedDeviceEvents.isEmpty {
                                VStack(alignment: .leading, spacing: 10) {
                                    Text("Device Events")
                                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                                        .foregroundStyle(NotrusPalette.ink)

                                    ForEach(model.linkedDeviceEvents.prefix(6), id: \.id) { event in
                                        Text(deviceEventSummary(event))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Create Another Profile")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            AdaptiveFieldRow {
                                LabeledField(label: "Display name") {
                                    TextField("Display name", text: $model.onboardingDisplayName)
                                        .textFieldStyle(.roundedBorder)
                                }
                            } trailing: {
                                LabeledField(label: "Username") {
                                    TextField("username", text: $model.onboardingUsername)
                                        .textFieldStyle(.roundedBorder)
                                }
                            }

                            Button(model.isBusy ? "Creating..." : "Create Device-Protected Profile") {
                                Task {
                                    await model.createIdentity()
                                }
                            }
                            .buttonStyle(PrimaryActionButtonStyle())
                            .disabled(model.isBusy)
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Contact Verification")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            Text("First contact stays unverified on this Mac. If a contact key changes, Notrus will surface a security event and stop treating the new key as trusted until you review it.")
                                .font(.callout)
                                .foregroundStyle(.secondary)

                            if model.visibleContactRecords.isEmpty {
                                Text("No contacts have been observed on this Mac yet.")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            } else {
                                VStack(spacing: 12) {
                                    ForEach(model.visibleContactRecords) { record in
                                        VStack(alignment: .leading, spacing: 10) {
                                            ViewThatFits(in: .horizontal) {
                                                HStack(alignment: .top, spacing: 12) {
                                                    contactRecordHeader(record)
                                                    Spacer()
                                                    contactRecordActions(record)
                                                }

                                                VStack(alignment: .leading, spacing: 12) {
                                                    contactRecordHeader(record)
                                                    contactRecordActions(record)
                                                }
                                            }

                                            VStack(alignment: .leading, spacing: 6) {
                                                Text("Safety number")
                                                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                                                    .foregroundStyle(.secondary)
                                                Text(model.safetyNumber(for: record.userId) ?? record.observedFingerprint)
                                                    .font(.system(.footnote, design: .monospaced))
                                                    .textSelection(.enabled)
                                                    .foregroundStyle(NotrusPalette.ink)
                                            }
                                        }
                                        .padding(16)
                                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                                    }
                                }
                            }

                            if !model.activeSecurityEvents.isEmpty {
                                VStack(alignment: .leading, spacing: 10) {
                                    Text("Security Events")
                                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                                        .foregroundStyle(.secondary)
                                    ForEach(model.activeSecurityEvents) { event in
                                        VStack(alignment: .leading, spacing: 10) {
                                            SecurityEventRow(event: event, compact: false)
                                            if event.requiresAction == false {
                                                Button("Dismiss") {
                                                    model.dismissSecurityEvent(event.id)
                                                }
                                                .buttonStyle(SecondaryActionButtonStyle())
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                        VStack(alignment: .leading, spacing: 14) {
                            Text("Recovery Archive")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundStyle(NotrusPalette.ink)

                            Text("Device-vault profiles can be exported as encrypted recovery archives and imported on another Mac later. Legacy hardware-pinned profiles stay local-only.")
                                .font(.callout)
                                .foregroundStyle(.secondary)

                            LabeledField(label: "Export passphrase") {
                                SecureField("At least 8 characters", text: $exportPassphrase)
                                    .textFieldStyle(.roundedBorder)
                            }

                            Button("Export Active Profile") {
                                Task {
                                    guard let prepared = await model.prepareCurrentAccountExport(passphrase: exportPassphrase) else {
                                        return
                                    }
                                    preparedExport = prepared
                                    exportPickerPresented = true
                                }
                            }
                            .buttonStyle(PrimaryActionButtonStyle())
                            .disabled(model.currentIdentity == nil || model.isBusy)

                            Divider()

                            LabeledField(label: "Import passphrase") {
                                SecureField("Passphrase used when the archive was created", text: $importPassphrase)
                                    .textFieldStyle(.roundedBorder)
                            }

                            Button("Import Recovery Archive") {
                                importPickerPresented = true
                            }
                            .buttonStyle(SecondaryActionButtonStyle())
                            .disabled(model.isBusy)
                        }
                        .padding(18)
                        .background(NotrusPalette.panelStrong, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                    }
                }
            }
            .frame(minWidth: 440, idealWidth: 860, minHeight: 720)
            .padding(28)
        }
        .fileExporter(
            isPresented: $exportPickerPresented,
            document: preparedExport?.document,
            contentType: .json,
            defaultFilename: preparedExport?.defaultFileName
        ) { result in
            if let preparedExport {
                model.completePreparedExport(preparedExport, result: result)
            }
            if case .success = result {
                exportPassphrase = ""
            }
            preparedExport = nil
        }
        .fileImporter(
            isPresented: $importPickerPresented,
            allowedContentTypes: [.json],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else {
                    return
                }
                let passphrase = importPassphrase
                importPassphrase = ""
                Task {
                    await model.importAccount(from: url, passphrase: passphrase)
                }
            case .failure(let error):
                let nsError = error as NSError
                if nsError.domain != NSCocoaErrorDomain || nsError.code != NSUserCancelledError {
                    model.errorMessage = error.localizedDescription
                }
            }
        }
    }

    @ViewBuilder
    private func profileIdentitySummary(_ profile: LocalIdentity) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(profile.displayName)
                .font(.system(size: 15, weight: .semibold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
                .lineLimit(2)
            Text("@\(profile.username)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
    }

    @ViewBuilder
    private func inventoryRow(label: String, value: String, trailing: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(value)
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(NotrusPalette.ink)
                    .lineLimit(1)
                    .textSelection(.enabled)
                Spacer(minLength: 0)
                if let trailing, !trailing.isEmpty {
                    Text(trailing)
                        .font(.caption)
                        .foregroundStyle(NotrusPalette.muted)
                }
            }
        }
    }

    @ViewBuilder
    private func profileTrailingActions(_ profile: LocalIdentity) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                StorageBadge(storageMode: profile.storageMode)
                if profile.id == model.currentIdentity?.id {
                    MetadataChip(label: "Active")
                } else {
                    Button("Switch") {
                        Task {
                            await model.switchIdentity(to: profile.id)
                        }
                    }
                    .buttonStyle(SecondaryActionButtonStyle())
                    .disabled(model.isBusy)
                }
                Button("Delete", role: .destructive) {
                    Task {
                        await model.deleteIdentity(profile.id)
                    }
                }
                .buttonStyle(SecondaryActionButtonStyle())
                .disabled(model.isBusy)
            }
            VStack(alignment: .leading, spacing: 10) {
                StorageBadge(storageMode: profile.storageMode)
                if profile.id == model.currentIdentity?.id {
                    MetadataChip(label: "Active")
                } else {
                    Button("Switch") {
                        Task {
                            await model.switchIdentity(to: profile.id)
                        }
                    }
                    .buttonStyle(SecondaryActionButtonStyle())
                    .disabled(model.isBusy)
                }
                Button("Delete", role: .destructive) {
                    Task {
                        await model.deleteIdentity(profile.id)
                    }
                }
                .buttonStyle(SecondaryActionButtonStyle())
                .disabled(model.isBusy)
            }
        }
    }

    @ViewBuilder
    private func contactRecordHeader(_ record: ContactTrustRecord) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                contactRecordSummary(record)
                TrustBadge(status: record.status)
                if record.blockedAt != nil {
                    MetadataChip(label: "Blocked")
                }
            }
            VStack(alignment: .leading, spacing: 8) {
                contactRecordSummary(record)
                HStack(spacing: 10) {
                    TrustBadge(status: record.status)
                    if record.blockedAt != nil {
                        MetadataChip(label: "Blocked")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func contactRecordActions(_ record: ContactTrustRecord) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                verifyButton(record)
                reportButton(record)
                blockButton(record)
                deleteContactButton(record)
            }
            VStack(alignment: .leading, spacing: 10) {
                verifyButton(record)
                reportButton(record)
                blockButton(record)
                deleteContactButton(record)
            }
        }
    }

    @ViewBuilder
    private func contactRecordSummary(_ record: ContactTrustRecord) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(record.displayName)
                .font(.system(size: 15, weight: .semibold, design: .rounded))
                .foregroundStyle(NotrusPalette.ink)
                .lineLimit(2)
            Text("@\(record.username)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
    }

    private func verifyButton(_ record: ContactTrustRecord) -> some View {
        Button("Verify") {
            Task {
                await model.verifyContact(record.userId)
            }
        }
        .buttonStyle(SecondaryActionButtonStyle())
        .disabled(model.isBusy)
    }

    private func reportButton(_ record: ContactTrustRecord) -> some View {
        Button("Report") {
            Task {
                await model.reportContact(record.userId)
            }
        }
        .buttonStyle(SecondaryActionButtonStyle())
        .disabled(model.isBusy)
    }

    private func blockButton(_ record: ContactTrustRecord) -> some View {
        Button(record.blockedAt == nil ? "Block" : "Unblock") {
            if record.blockedAt == nil {
                model.blockContact(record.userId)
            } else {
                model.unblockContact(record.userId)
            }
        }
        .buttonStyle(SecondaryActionButtonStyle())
        .disabled(model.isBusy)
    }

    private func deleteContactButton(_ record: ContactTrustRecord) -> some View {
        Button("Delete", role: .destructive) {
            model.deleteLocalContact(record.userId)
        }
        .buttonStyle(SecondaryActionButtonStyle())
        .disabled(model.isBusy)
    }
}

struct PrimaryActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 14, weight: .semibold, design: .rounded))
            .foregroundStyle(.white)
            .padding(.horizontal, 18)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [
                                NotrusPalette.accent.opacity(configuration.isPressed ? 0.8 : 1),
                                NotrusPalette.depth.opacity(configuration.isPressed ? 0.85 : 1)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
            )
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .animation(.easeOut(duration: 0.14), value: configuration.isPressed)
    }
}

struct SecondaryActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 14, weight: .semibold, design: .rounded))
            .foregroundStyle(NotrusPalette.ink)
            .padding(.horizontal, 16)
            .padding(.vertical, 11)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(NotrusPalette.panelStrong.opacity(configuration.isPressed ? 0.78 : 1))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(NotrusPalette.hairline, lineWidth: 1)
            )
    }
}

private func shortTimestamp(_ isoString: String) -> String {
    let parser = ISO8601DateFormatter()
    if let date = parser.date(from: isoString) {
        return date.formatted(date: .omitted, time: .shortened)
    }
    return isoString
}

private func relativeDate(_ isoString: String) -> String {
    let parser = ISO8601DateFormatter()
    guard let date = parser.date(from: isoString) else {
        return isoString
    }
    return RelativeDateTimeFormatter().localizedString(for: date, relativeTo: Date())
}

private func deviceEventSummary(_ event: RelayDeviceEvent) -> String {
    let action: String
    switch event.kind {
    case "device-added":
        action = "Linked"
    case "device-revoked":
        action = "Revoked"
    case "account-reset":
        action = "Reset"
    default:
        action = event.kind.capitalized
    }
    let label = event.label ?? event.deviceId
    return "\(action) \(label) \(relativeDate(event.createdAt))."
}

private func formattedByteCount(_ byteCount: Int) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(byteCount), countStyle: .file)
}
