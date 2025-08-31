// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import CKTap
import XCTest

final class CKTapTests: XCTestCase {
  func testEmulatorTransport() async throws {
    print("Test with card emulator transport")
    let cardEmulator = CardEmulator()

    let card = try await toCktap(transport: cardEmulator)

    switch card {
    case .satsCard(let satsCard):
      print("Handling SatsCard with status: \(await satsCard.status())")
      let address: String = try await satsCard.address()
      print("SatsCard address: \(address)")
      XCTAssertEqual(address, "bc1qdu05evh9kw0w482lfl2ktxm6ylp060km28z8fr")
    case .tapSigner(let tapSigner):
      let status = await tapSigner.status()
      print("Handling TapSigner with status: \(status)")
      let public_key = try await tapSigner.read(cvc: "123456")
      print("TapSigner public key: \(Array(public_key))")
      XCTAssertEqual(status.ver, "1.0.3")
    case .satsChip(let satsChip):
      let status = await satsChip.status()
      print("Handling SatsChip with status: \(status)")
      XCTAssertEqual(status.ver, "1.0.3")
    }
  }
  func testNfcUrl() async throws {
    let cardEmulator = CardEmulator()
    let card = try await toCktap(transport: cardEmulator)
    switch card {
    case .satsCard(let satsCard):
      let url: String = try await satsCard.nfc()
      print("SatsCard url: \(url)")
    case .tapSigner(let tapSigner):
      let url: String = try await tapSigner.nfc()
      print("TapSigner url: \(url)")
    case .satsChip(let satsChip):
      let url: String = try await satsChip.nfc()
      print("SatsChip url: \(url)")
    }
  }
  func testXpub() async throws {
    let cardEmulator = CardEmulator()
    let card = try await toCktap(transport: cardEmulator)
    switch card {
    case .satsCard(_):
      print("SatsCard does not support he xpub command.")
    case .tapSigner(let tapSigner):
      let xpub: String = try await tapSigner.xpub(master: true, cvc: "123456").toString()
      print("TapSigner master xpub: \(xpub)")
    case .satsChip(let satsChip):
      let xpub: String = try await satsChip.xpub(master: false, cvc: "123456").toString()
      print("SatsChip xpub: \(xpub)")
    }
  }
}
