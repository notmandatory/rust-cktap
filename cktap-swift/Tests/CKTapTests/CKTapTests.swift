import XCTest
import CKTap
import CryptoTokenKit

final class CKTapTests: XCTestCase {
    func testHelloRandom() throws {
        let nonce = randNonce()
        print("Random: \(nonce)")
    }

    func testAddress() throws {
        print("Test getting an address")
        let manager = TKSmartCardSlotManager()
        let slots = manager.slotNames

        if slots.isEmpty {
            print("No smart card slots available.")
            return
        } else {
            if let firstSlotName = slots.first {
                    print("Connecting to slot: \(firstSlotName)")
                    manager.getSlot(withName:firstSlotName) { slot in
                        guard let smartCardSlot = slot?.makeSmartCard() else {
                            print("Failed to create smart card from slot.")
                            return
                        }

                        smartCardSlot.beginSession(reply:) { success, error in
                            if success {
                                print("Session started successfully.")
                            } else {
                                print("Failed to start session: \(String(describing: error))")
                            }
                        }
                    }
                }
        }
    }
}
