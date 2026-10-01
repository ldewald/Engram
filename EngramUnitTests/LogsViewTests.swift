@testable import Engram
import AppKit
import SwiftUI
import XCTest

@MainActor
final class LogsViewTests: XCTestCase {
    private static let longMessage = Array(repeating: "memories were split across project scopes", count: 8)
        .joined(separator: " ")

    func testExpansionFollowsEntryContentWhenPositionsShift() {
        let store = LogsStore()
        let entry = LogEntry(id: 5, timestamp: nil, source: "maintenance", message: "a", raw: "a")
        store.toggleExpanded(entry)

        // A capped log gaining a line shifts every id; expansion must stay on the same line.
        let shifted = LogEntry(id: 4, timestamp: nil, source: "maintenance", message: "a", raw: "a")
        let newOccupant = LogEntry(id: 5, timestamp: nil, source: "maintenance", message: "b", raw: "b")
        XCTAssertTrue(store.isExpanded(shifted))
        XCTAssertFalse(store.isExpanded(newOccupant))

        store.toggleExpanded(shifted)
        XCTAssertFalse(store.isExpanded(entry))
    }

    func testTimestampStaysOnOneLine() throws {
        let time = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-09-30T16:40:00Z"))
        func height(_ entry: LogEntry) -> CGFloat {
            NSHostingView(rootView: LogRow(entry: entry, isExpanded: false) {}.frame(width: 280)).fittingSize.height
        }
        let stamped = LogEntry(id: 0, timestamp: time, source: "memory", message: "recall", raw: "stamped")
        let plain = LogEntry(id: 1, timestamp: nil, source: "memory", message: "recall", raw: "plain")
        XCTAssertEqual(height(stamped), height(plain), "A wrapped timestamp makes one-line rows taller")
    }

    func testClickingTruncatedEntryPushesNextRowDownInsteadOfDrawingOverIt() throws {
        let long = LogEntry(id: 0, timestamp: nil, source: "maintenance", message: Self.longMessage, raw: "long")
        let next = LogEntry(id: 1, timestamp: nil, source: "maintenance", message: "next", raw: "next")
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
        pumpEvents()
        try XCTSkipUnless(window.isKeyWindow, "SwiftUI only delivers taps to the key window")

        let collapsed = try XCTUnwrap(frames.rows["long"])
        click(window, at: CGPoint(x: 80, y: collapsed.minY + 8))

        let expanded = try XCTUnwrap(frames.rows["long"])
        let nextRow = try XCTUnwrap(frames.rows["next"])
        XCTAssertGreaterThan(expanded.height, collapsed.height * 2, "Clicking a truncated entry expands its row")
        XCTAssertGreaterThanOrEqual(nextRow.minY, expanded.maxY, "Rows below move down to make room")
        for textView in textViews(in: host) {
            let drawn = frameInWindow(of: textView, window)
            XCTAssertLessThanOrEqual(drawn.maxY, nextRow.minY + 0.5,
                                     "Selectable text must not draw past its row into the next one")
        }
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
        pumpEvents()
    }

    private func pumpEvents() {
        let deadline = Date(timeIntervalSinceNow: 0.5)
        while Date() < deadline {
            if let event = NSApp.nextEvent(matching: .any, until: Date(timeIntervalSinceNow: 0.05),
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
            Spacer(minLength: 0)
        }
        .frame(width: 280, height: 600, alignment: .top)
    }
}
