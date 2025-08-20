import XCTest
import CKTap

final class CKTapTests: XCTestCase {
    func testHelloRandom() throws {
        let nonce = randNonce()
        print("Random: \(nonce)")
    }

    func testEmulatorTransport() async throws {
        print("Test with card emulator transport")
        let cardEmulator = CardEmulator()
        
        let card: CkTapCard
        do {
            card = try await toCktap(transport: cardEmulator)
        } catch {
            throw CkTapError.Core(msg: "Failed to create CkTap instance: \(error.localizedDescription)")
        }
        
        switch card {
            case .satsCard(let satsCard):
            print("Handling SatsCard with version: \(await satsCard.ver())")
            let address: String = try await satsCard.address()
            print("SatsCard address: \(address)")
            XCTAssertEqual(address, "bc1qdu05evh9kw0w482lfl2ktxm6ylp060km28z8fr")
            case .tapSigner(let tapSigner):
            print("Handling TapSigner with version: \(await tapSigner.ver())")
            let public_key = try await tapSigner.read(cvc: "123456")
            print("TapSigner public key: \(Array(public_key))")
            case .satsChip(let satsChip):
                print("Handling SatsChip with version: \(await satsChip.ver())")
            }
        }
    }
