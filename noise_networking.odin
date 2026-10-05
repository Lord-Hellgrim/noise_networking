package noise_networking


import "core:crypto/noise"
import "core:net"
import "core:fmt"
import "core:encoding/endian"
import "core:time"


Connection :: struct {
    peer: net.Endpoint,
    socket: net.TCP_Socket,
    cipherstates: noise.Cipher_States,
}

ConnectionStatus :: enum {
    ok,
    handshake_pending,
    handshake_complete,
    nil_message_read,
    dial_error,
    send_error,
    recv_error,
    handshakestate_initialization_error,
}

DEFAULT_PROTOCOL_NAME :: "Noise_NN_25519_AESGCM_SHA256"

initiate_connection_all_the_way :: proc(endpoint: net.Endpoint, protocol := DEFAULT_PROTOCOL_NAME, options := net.DEFAULT_TCP_OPTIONS) -> (Connection, ConnectionStatus) {
    connection : Connection

    socket, dial_error := net.dial_tcp(endpoint, options = options)
    if dial_error != net.Dial_Error.None {
        return {}, .dial_error
    }

    handshakestate : noise.Handshake_State
    ini_status := noise.handshake_init(&handshakestate, true, nil, nil, nil, DEFAULT_PROTOCOL_NAME )
    if ini_status != .Ok {
        return {}, .handshakestate_initialization_error
    }

    handshake_status : noise.Status
    input_message : []u8
    cipherstates : noise.Cipher_States
    output_message: []u8
    message_from: []u8
    recv_error : net.TCP_Recv_Error
    for handshake_status != .Handshake_Complete {
        output_message, message_from, handshake_status = noise.handshake_initiator_step(&handshakestate, input_message)
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

establish_connection_all_the_way :: proc(socket: net.TCP_Socket, peer: net.Endpoint, protocol := DEFAULT_PROTOCOL_NAME) -> (Connection, ConnectionStatus) {
    connection : Connection
    
    handshakestate : noise.Handshake_State
    ini_status := noise.handshake_init(&handshakestate, false, nil, nil, nil, protocol)
    if ini_status != .Ok {
        return {}, .handshakestate_initialization_error
    }

    handshake_status : noise.Status
    recv_error : net.TCP_Recv_Error
    cipherstates : noise.Cipher_States
    input_message : []u8
    message_to : []u8
    message_from : []u8
    for handshake_status != .Handshake_Complete {
        input_message, recv_error = read_length_prefixed(socket)
        if len(input_message) == 0 {
            panic("nil message read")
        }
        fmt.println("message received")
        if recv_error != .None {
            return {}, .recv_error
        }
        message_to, message_from, handshake_status = noise.handshake_responder_step(&handshakestate, input_message)
        send_status := send_length_prefixed(socket, message_to)
        if send_status != .ok {
            return {}, send_status
        }
        if handshake_status == .Handshake_Complete {
            break
        }
    }

    connection.socket = socket
    connection.cipherstates = cipherstates
    connection.peer = peer

    return connection, .ok
}

initiate_connection_step :: proc(handshakestate: ^noise.Handshake_State, socket: net.TCP_Socket, peer: net.Endpoint) -> (Connection, ConnectionStatus) {
    connection : Connection

    input_message : []u8
    recv_error : net.TCP_Recv_Error
    if handshakestate.current_message != 0 {
        input_message, recv_error := read_length_prefixed(socket)
        if recv_error != .None {
            return {}, .recv_error
        }
    }

    message_from, message_to, handshake_status := noise.handshake_initiator_step(handshakestate, input_message)

    cipherstates : noise.Cipher_States
    if handshake_status == .Handshake_Complete {
        connection.socket = socket
        split_status := noise.handshake_split(handshakestate, &cipherstates)
        if split_status == .Ok {
            connection.cipherstates = cipherstates
        }
        connection.peer = peer
        return connection, .handshake_complete
    } else {
        send_status := send_length_prefixed(socket, message_to)
        if send_status != .ok {
            return {}, send_status
        } else {
            return {}, .handshake_pending
        }
    }
}

establish_connection_step :: proc(handshakestate: ^noise.Handshake_State, socket: net.TCP_Socket, peer: net.Endpoint) -> (Connection, ConnectionStatus) {
    connection : Connection
    
    input_message, recv_error := read_length_prefixed(socket)
    if len(input_message) == 0 {
        return {},.nil_message_read
    }
    fmt.println("message received")
    if recv_error != .None {
        return {}, .recv_error
    }
    message_to, message_from, handshake_status := noise.handshake_responder_step(handshakestate, input_message)
    if handshake_status == .Handshake_Complete {
        connection.socket = socket
        cipherstates : noise.Cipher_States
        split_status := noise.handshake_split(handshakestate, &cipherstates)
        if split_status == .Ok {
            connection.cipherstates = cipherstates
        } else {
            return {}, .handshakestate_initialization_error
        }
        connection.peer = peer

        return connection, .handshake_complete
    }
    send_status := send_length_prefixed(socket, message_to)
    if send_status != .ok {
        return {}, send_status
    } else {
        return {}, .handshake_pending
    }
}

send_data :: proc(connection: ^Connection, data: []u8, ad: []u8 = nil, allocator := context.allocator) -> ConnectionStatus {
    
    message, prepare_status := noise.seal_message(&connection.cipherstates, ad, data, allocator = allocator)
    nonce : u64
    if connection.cipherstates.initiator {
        nonce = connection.cipherstates.c1_i_to_r.n - 1
    } else {
        nonce = connection.cipherstates.c2_r_to_i.n - 1
    }
    message_len := u64(len(message) + 8)
    nonce_bytes : [8]u8
    endian.put_u64(nonce_bytes[:], .Little, nonce)
    message_len_bytes : [8]u8
    endian.put_u64(message_len_bytes[:], .Little, message_len)
    fmt.println(message_len_bytes)

    bytes_written, send_status := net.send_tcp(connection.socket, message_len_bytes[:])
    fmt.println("bytes written: ", bytes_written)
    bytes_written, send_status = net.send_tcp(connection.socket, nonce_bytes[:])
    fmt.println("bytes written: ", bytes_written)
    bytes_written, send_status = net.send_tcp(connection.socket, message)
    if send_status != .None {
        return .send_error
    }

    return .ok
}

receive_data :: proc(connection : ^Connection, ad: []u8 = nil) -> ([]u8, u64, ConnectionStatus) {
    data, status := read_length_prefixed(connection.socket)
    fmt.println("Data: ", data)
    fmt.println(status)
    nonce := u64(from_le_bytes(data[:8]))
    data = data[8:]
    message, noise_status := noise.open_message(&connection.cipherstates, ad, data)
    if noise_status != .Ok {
        return nil, nonce, .recv_error
    }

    return message, nonce, .ok
}

send_length_prefixed :: proc(socket: net.TCP_Socket, message: []u8) -> ConnectionStatus {
    message_len : [8]u8
    endian.put_u64(message_len[:], .Little, u64(len(message)))
    fmt.println("message_len: ", message_len)
    bytes_written, send_status := net.send_tcp(socket, message_len[:])
    fmt.println("bytes written: ", bytes_written)
    bytes_written, send_status = net.send_tcp(socket, message)
    fmt.println("bytes written: ", bytes_written)
    if send_status != .None {
        return .send_error
    }

    return .ok
}

// Strips the length prefix from the data packet
read_length_prefixed :: proc(socket: net.TCP_Socket, allocator := context.allocator) -> ([]u8, net.TCP_Recv_Error) {
    length : [8]u8
    bytes_received, status := net.recv_tcp(socket, length[:])
    fmt.println("Bytes received: ", bytes_received)
    if status != .None {
        panic("AAAAAAA")
    }
    len, _ := endian.get_u64(length[:], .Little)

    result := make([]u8, len)
    bytes_received  = 0
    status = .None
    for u64(bytes_received) < len || status != .None {
        bytes_received, status = net.recv_tcp(socket, result[bytes_received:])
        time.sleep(time.Second)
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
        } else {
            fmt.println("FAILED TO CONNECT")
            return
        }

        test_data :[10]u8 = {1,2,3,4,5,6,7,8,9,10}
        send_status := send_data(&connection, test_data[:])
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

        hs : noise.Handshake_State
        hs_status := noise.handshake_init(&hs, false, nil, nil, nil, DEFAULT_PROTOCOL_NAME)

        connection_status : ConnectionStatus = .handshake_pending
        connection : Connection
        for  {
            connection, connection_status = establish_connection_step(&hs, socket, server_address)
            if connection_status == .handshake_pending {
                continue
            } else if connection_status == .handshake_complete {
                data, nonce, recv_status := receive_data(&connection)
                fmt.println("Recv status: ", recv_status)
                fmt.println("NONCE: ", nonce)
                fmt.println(data)
        
                fmt.println("SUCCESS!!")
                break
            } else {
                fmt.println(connection_status)
                break
            }
        
        }


        // connection, connection_status := establish_connection_all_the_way(socket, source)
        // fmt.println("Established connection...")

        // if connection_status == .ok {
        //     fmt.println("SUCCESS!!")
        // }
        // data, recv_status := receive_data(&connection)
        // fmt.println("Recv status: ", recv_status)
        // fmt.println(data)
    }
}