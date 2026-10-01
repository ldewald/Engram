@testable import Engram
import AppKit
import SwiftUI
import XCTest

@MainActor
final class LogsViewTests: XCTestCase {
    func testEntryIdsSurviveTheTailMoving() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("engram-log-ids-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("maintenance.log")
        let source = LogSource(id: "maintenance", label: "Maintenance", path: file.path, icon: "", color: .orange)
        try (0..<LogTailReader.maximumLines).map { "line \($0)\n" }.joined()
            .write(to: file, atomically: true, encoding: .utf8)
        let before = LogTailReader.read(sources: [source])

        // At the line cap, one more line pushes the oldest out of the tail.
        let handle = try FileHandle(forWritingTo: file)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("line 500\n".utf8))
        try handle.close()
        let after = LogTailReader.read(sources: [source])

        XCTAssertEqual(after.first?.raw, "line 1")
        let survivor = try XCTUnwrap(before.first { $0.raw == "line 250" })
        XCTAssertEqual(after.first { $0.raw == "line 250" }?.id, survivor.id)
        XCTAssertEqual(Set(after.map(\.id)).count, after.count)
    }

    func testTimestampStaysOnOneLine() throws {
        let time = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-09-30T16:40:00Z"))
        func height(_ entry: LogEntry) -> CGFloat {
            NSHostingView(rootView: LogRow(entry: entry, isExpanded: false) {}.frame(width: 280)).fittingSize.height
        }
        let stamped = LogEntry(id: .init(source: "memory", offset: 0), timestamp: time, source: "memory",
                               message: "recall", raw: "stamped")
        let plain = LogEntry(id: .init(source: "memory", offset: 1), timestamp: nil, source: "memory",
                             message: "recall", raw: "plain")
        XCTAssertEqual(height(stamped), height(plain), "A wrapped timestamp makes one-line rows taller")
    }

    func testClickingTruncatedEntryPushesNextRowDownInsteadOfDrawingOverIt() throws {
        let message = Array(repeating: "memories were split across project scopes", count: 8).joined(separator: " ")
        let long = LogEntry(id: .init(source: "maintenance", offset: 0), timestamp: nil, source: "maintenance",
                            message: message, raw: "long")
        let next = LogEntry(id: .init(source: "maintenance", offset: 1), timestamp: nil, source: "maintenance",
                            message: "next", raw: "next")
        let frames = RowFrames()
        let host = NSHostingView(rootView: RowsHarness(entries: [long, next], store: LogsStore(), frames: frames))
        // A non-activating panel can become key while the test host is in the
        // background; macOS won't let a background app activate itself.
        let window = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 280, height: 600),
                             styleMask: [.titled, .nonactivatingPanel], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = host
        if NSApp.activationPolicy() == .prohibited { NSApp.setActivationPolicy(.accessory) }
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        pumpEvents(timeout: 0.3) // SwiftUI ignores clicks that arrive before it settles
        try XCTSkipUnless(window.isKeyWindow, "SwiftUI only delivers taps to the key window")

        let collapsed = try XCTUnwrap(frames.rows["long"])
        click(window, at: CGPoint(x: 80, y: collapsed.minY + 8))
        pumpEvents { (frames.rows["long"]?.height ?? 0) > collapsed.height * 2 }
        let expanded = try XCTUnwrap(frames.rows["long"])
        XCTAssertGreaterThan(expanded.height, collapsed.height * 2, "Clicking a truncated entry expands its row")

        // AppKit only installs the selectable text view once the text is clicked.
        click(window, at: CGPoint(x: 80, y: expanded.midY))
        pumpEvents { !textViews(in: host).isEmpty }
        XCTAssertEqual(frames.rows["long"], expanded, "Clicking expanded text selects it instead of collapsing")
        let nextRow = try XCTUnwrap(frames.rows["next"])
        let textView = try XCTUnwrap(textViews(in: host).first)
        XCTAssertLessThanOrEqual(frameInWindow(of: textView, window).maxY, nextRow.minY + 0.5,
                                 "Selectable text must not draw past its row into the next one")
    }

    // MARK: - Helpers

    /// Delivers a click the way AppKit would, including to any text-selection
    /// tracking loop that waits for its mouse-up on the event queue.
    /// `point` is top-left window coordinates, the space `.global` frames use.
    private func click(_ window: NSWindow, at point: CGPoint) {
        let location = NSPoint(x: point.x, y: window.frame.height - point.y)
        func event(_ type: NSEvent.EventType) -> NSEvent {
            NSEvent.mouseEvent(with: type, location: location, modifierFlags: [],
                               timestamp: ProcessInfo.processInfo.systemUptime,
                               windowNumber: window.windowNumber, context: nil,
                               eventNumber: 0, clickCount: 1, pressure: 1)!
        }
        NSApp.postEvent(event(.leftMouseUp), atStart: false)
        window.sendEvent(event(.leftMouseDown))
    }

    /// Dispatches queued events until `condition` holds or `timeout` passes.
    private func pumpEvents(timeout: TimeInterval = 2, until condition: () -> Bool = { false }) {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while !condition(), Date() < deadline {
            if let event = NSApp.nextEvent(matching: .any, until: Date(timeIntervalSinceNow: 0.01),
                                           inMode: .default, dequeue: true) {
                NSApp.sendEvent(event)
            }
        }
    }

    private func frameInWindow(of view: NSView, _ window: NSWindow) -> CGRect {
        let rect = view.convert(view.bounds, to: nil)
        return CGRect(x: rect.minX, y: window.frame.height - rect.maxY, width: rect.width, height: rect.height)
    }

    private func textViews(in view: NSView) -> [NSTextView] {
        (view as? NSTextView).map { [$0] } ?? view.subviews.flatMap(textViews(in:))
    }
}

@MainActor
private final class RowFrames {
    var rows: [String: CGRect] = [:]
}

private struct RowsHarness: View {
    let entries: [LogEntry]
    let store: LogsStore
    let frames: RowFrames

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            ForEach(entries) { entry in
                LogRow(entry: entry, isExpanded: store.isExpanded(entry)) { store.toggleExpanded(entry) }
                    .onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: {
                        frames.rows[entry.raw] = $0
                    }
            }
        }
        .frame(width: 280, height: 600, alignment: .top)
    }
}
