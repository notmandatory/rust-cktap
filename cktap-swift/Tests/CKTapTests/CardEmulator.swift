import CKTap
import Foundation

// Example of a custom Swift implementation of the CkTransport callback interface
// start the emulator with the repo level command: just start
// stop the emulator with: just stop
// see other emulator options with: just help
final class CardEmulator: CkTransport {
  let SELECT_CLA_INS_P1P2: [UInt8] = [0x00, 0xA4, 0x04, 0x00]
  let APP_ID: [UInt8] = [0x0F, 0xF0] + Array("CoinkiteCARDv1".utf8)
  // CBOR encoded status command, { cmd: "status" }
  let STATUS_COMMAND: [UInt8] = [
    0xA1, 0x63, 0x63, 0x6d, 0x64, 0x66, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
  ]

  func transmitApdu(commandApdu: Data) async throws -> Data {
    let socketPath = "/tmp/ecard-pipe"

    // Create a Unix domain socket
    let socketFd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard socketFd != -1 else {
      throw CkTapError.Transport(
        msg: "Failed to create socket: \(String(cString: strerror(errno)))")
    }
    defer {
      close(socketFd)
    }

    // Set up the socket address structure
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)

    // Copy the socket path to sun_path
    let pathBytes = socketPath.utf8CString
    guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
      throw CkTapError.Transport(msg: "Socket path too long")
    }

    withUnsafeMutableBytes(of: &addr.sun_path) { ptr in
      pathBytes.withUnsafeBufferPointer { pathPtr in
        ptr.copyMemory(from: UnsafeRawBufferPointer(pathPtr))
      }
    }

    // Connect to the socket
    let connectResult = withUnsafePointer(to: &addr) { ptr in
      ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
        connect(socketFd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }

    guard connectResult != -1 else {
      throw CkTapError.Transport(
        msg: "Failed to connect to socket: \(String(cString: strerror(errno)))")
    }

    // Prepare the command data
    let selectApdu: Data = Data(SELECT_CLA_INS_P1P2 + APP_ID)
    let commandData: Data
    if commandApdu == selectApdu {
      commandData = Data(STATUS_COMMAND)
    } else {
      commandData = commandApdu[5...]  // remove APDU header (first 5 bytes)
    }

    // Write data to the socket
    let writeResult = commandData.withUnsafeBytes { ptr in
      send(socketFd, ptr.baseAddress!, commandData.count, 0)
    }

    guard writeResult != -1 else {
      throw CkTapError.Transport(
        msg: "Failed to write to socket: \(String(cString: strerror(errno)))")
    }

    guard writeResult == commandData.count else {
      throw CkTapError.Transport(
        msg: "Incomplete write to socket: wrote \(writeResult) of \(commandData.count) bytes")
    }

    // Read response from the socket
    let bufferSize = 4096
    var buffer = [UInt8](repeating: 0, count: bufferSize)

    let readResult = recv(socketFd, &buffer, bufferSize, 0)
    guard readResult != -1 else {
      throw CkTapError.Transport(
        msg: "Failed to read from socket: \(String(cString: strerror(errno)))")
    }

    guard readResult > 0 else {
      throw CkTapError.Transport(msg: "Socket connection closed by peer")
    }

    // Create Data from the received bytes
    let responseData = Data(buffer.prefix(readResult))

    return responseData
  }
}
