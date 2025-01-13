import XCTest
import CKTap

final class CKTapTests: XCTestCase {
    func testHelloRandom() throws {
        print("Hello!")
        let nonce = randNonce()
        print("Random: \(nonce)")
    }
}
