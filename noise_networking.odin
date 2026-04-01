package noise_networking


import "../noise"
import "core:net"
import "core:fmt"


Connection :: struct {
    peer: net.Endpoint,
    socket: net.TCP_Socket,
    cipherstates: noise.CipherStates,
}

ConnectionStatus :: enum {
    ok,
    handshake_pending,
    handshake_complete,
    dial_error,
    send_error,
    recv_error,
    handshakestate_initialization_error,
}

initiate_connection_all_the_way :: proc(endpoint: net.Endpoint, protocol := noise.DEFAULT_PROTOCOL, options := net.DEFAULT_TCP_OPTIONS) -> (Connection, ConnectionStatus) {
    connection : Connection

    socket, dial_error := net.dial_tcp(endpoint, options = options)
    if dial_error != net.Dial_Error.None {
        return {}, .dial_error
    }

    handshakestate, ini_status := noise.handshakestate_initialize(true, nil, nil, nil, nil, nil)
    if ini_status != .Ok {
        return {}, .handshakestate_initialization_error
    }

    handshake_status : noise.NoiseStatus
    input_message : []u8
    cipherstates : noise.CipherStates
    output_message : []u8
    recv_error : net.TCP_Recv_Error
    for handshake_status != .Handshake_Complete {
        cipherstates, output_message, handshake_status = noise.initiator_step(&handshakestate, input_message, nil)
        send_status := send_length_prefixed(socket, output_message)
        if send_status != .ok {
            return {}, send_status
        }
        if handshake_status == .Handshake_Complete {
            break
        }
        input_message, recv_error = read_length_prefixed(socket)
        fmt.println("input_message: ", input_message)
        if recv_error != .None {
            return {}, .recv_error
        }
    }

    connection.socket = socket
    connection.cipherstates = cipherstates
    connection.peer = endpoint
    
    return connection, .ok
}

establish_connection_all_the_way :: proc(socket: net.TCP_Socket, peer: net.Endpoint, protocol := noise.DEFAULT_PROTOCOL) -> (Connection, ConnectionStatus) {
    connection : Connection
    
    handshakestate, ini_status := noise.handshakestate_initialize(false, nil, nil, nil, nil, nil)
    if ini_status != .Ok {
        return {}, .handshakestate_initialization_error
    }

    handshake_status : noise.NoiseStatus
    recv_error : net.TCP_Recv_Error
    cipherstates : noise.CipherStates
    input_message : []u8
    output_message : []u8
    for handshake_status != .Handshake_Complete {
        input_message, recv_error = read_length_prefixed(socket)
        if len(input_message) == 0 {
            panic("nil message read")
        }
        fmt.println("message received")
        if recv_error != .None {
            return {}, .recv_error
        }
        cipherstates, output_message, handshake_status = noise.responder_step(&handshakestate, input_message, nil)
        if handshake_status == .Handshake_Complete {
            break
        }
        send_status := send_length_prefixed(socket, output_message)
        if send_status != .ok {
            return {}, send_status
        }
    }

    connection.socket = socket
    connection.cipherstates = cipherstates
    connection.peer = peer

    return connection, .ok
}

initiate_connection_step :: proc(handshakestate: ^noise.HandshakeState, socket: net.TCP_Socket, peer: net.Endpoint) -> (Connection, ConnectionStatus) {
    connection : Connection

    input_message : []u8
    recv_error : net.TCP_Recv_Error
    if handshakestate.current_pattern != 0 {
        input_message, recv_error := read_length_prefixed(socket)
        if recv_error != .None {
            return {}, .recv_error
        }
    }

    cipherstates, output_message, handshake_status := noise.initiator_step(handshakestate, input_message, nil)
    send_status := send_length_prefixed(socket, output_message)
    if send_status != .ok {
        return {}, send_status
    }

    if handshake_status == .Handshake_Complete {
        connection.socket = socket
        connection.cipherstates = cipherstates
        connection.peer = peer
        return connection, .handshake_complete
    } else {
        return {}, .handshake_pending
    }
}

establish_connection_step :: proc(handshakestate: ^noise.HandshakeState, socket: net.TCP_Socket, peer: net.Endpoint) -> (Connection, ConnectionStatus) {
    connection : Connection
    
    input_message, recv_error := read_length_prefixed(socket)
    if len(input_message) == 0 {
        panic("nil message read")
    }
    fmt.println("message received")
    if recv_error != .None {
        return {}, .recv_error
    }
    cipherstates, output_message, handshake_status := noise.responder_step(handshakestate, input_message, nil)
    if handshake_status == .Handshake_Complete {
        connection.socket = socket
        connection.cipherstates = cipherstates
        connection.peer = peer

        return connection, .handshake_complete
    }
    send_status := send_length_prefixed(socket, output_message)
    if send_status != .ok {
        return {}, send_status
    } else {
        return {}, .handshake_pending
    }
}

send_data :: proc(data: []u8, connection: ^Connection) -> ConnectionStatus {
    message, prepare_status := noise.prepare_message(&connection.cipherstates, data)

    message_len := noise.to_le_bytes(u64(len(message.main_body))) + 16
    bytes_written, send_status :=net.send_tcp(connection.socket, message_len[:])
    bytes_written, send_status = net.send_tcp(connection.socket, message.main_body)
    bytes_written, send_status = net.send_tcp(connection.socket, message.tag[:])
    if send_status != .None {
        return .send_error
    }

    return .ok
}

receive_data :: proc(connection : ^Connection) -> ([]u8, ConnectionStatus) {
    data, status := read_length_prefixed(connection.socket)
    message, noise_status := noise.open_message(&connection.cipherstates, noise.cryptobuffer_from_slice(data))
    if noise_status != .Ok {
        return nil, .recv_error
    }

    return message, .ok
}

send_length_prefixed :: proc(socket: net.TCP_Socket, message: []u8) -> ConnectionStatus {

    message_len := noise.to_le_bytes(u64(len(message)))
    bytes_written, send_status :=net.send_tcp(socket, message_len[:])
    bytes_written, send_status = net.send_tcp(socket, message)
    if send_status != .None {
        return .send_error
    }

    return .ok
}

read_length_prefixed :: proc(socket: net.TCP_Socket, allocator := context.allocator) -> ([]u8, net.TCP_Recv_Error) {
    length : [8]u8
    bytes_received, status := net.recv_tcp(socket, length[:])
    if status != .None {
        panic("AAAAAAA")
    }
    len := from_le_bytes(length[:])

    result := make([]u8, len)
    bytes_received  = 0
    status = .None
    for bytes_received < len || status != .None {
        bytes_received, status = net.recv_tcp(socket, result[bytes_received:])
    }

    return result, status
}

from_le_bytes :: proc(slice: []u8) -> int {
    x := int(slice[0] >> 0) + int(slice[1] >> 8) + int(slice[2] >> 16) + int(slice[3] >> 24) + int(slice[4] >> 32) + int(slice[5] >> 40) + int(slice[6] >> 48) + int(slice[7] >> 56);
    return x
}

main :: proc() {
    when ODIN_OS == .Windows {
        server_address, parsed := net.parse_endpoint("127.0.0.1:5000")
        connection, status := initiate_connection_all_the_way(server_address)
        if status == .ok {
            fmt.println("SUCCESS!!")
        }

        test_data :[10]u8 = {1,2,3,4,5,6,7,8,9,10}
        send_status := send_data(test_data[:], &connection)
        fmt.println("Send status: ", send_status)
    }

    when ODIN_OS == .Linux {
        fmt.println("Starting...")
        server_address, parsed := net.parse_endpoint("127.0.0.1:5000")
        fmt.println("Parsed endpoint...")
        if !parsed {
            panic("PARSING WRONG!!")
        }
        listener, listen_err := net.listen_tcp(server_address)
        fmt.println("Opened listener...")
        socket, source, status := net.accept_tcp(listener)

        connection, connection_status := establish_connection_all_the_way(socket, source)
        fmt.println("Established connection...")

        if connection_status == .ok {
            fmt.println("SUCCESS!!")
        }
        data, recv_status := receive_data(&connection)
        fmt.println("Recv status: ", recv_status)
        fmt.println(data)
    }
}