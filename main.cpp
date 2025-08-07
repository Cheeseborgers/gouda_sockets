
#include <iostream>

#include "base_socket.hpp"

int main()
{
    auto result = net::TCPServerSocket::create();

    if (!result.has_value()) {
        std::cerr << "Failed to create server socket\n";
        return 1;
    }

    // Move it into a local variable (no copying, no shared_ptr)
    auto server_socket = std::move(result.value());

    // Set option
    if (const auto opt = server_socket.set_option(net::SocketOption::NonBlocking, true); !opt) {
        std::cerr << "Failed to set non-blocking\n";
    }

    const auto addr = net::SocketAddress::any(8080);


    auto bind_result = server_socket.bind_and_listen(addr.value());
    if (bind_result.has_value()) {
        std::cout << "Server bound and listening successfully.\n";
    }
    else {
        std::cerr << "Error: " << net::error_to_string(bind_result.error()) << '\n';
    }

    while (true) {
        if (const auto client = server_socket.accept()) {
            std::array<std::byte, 1024> buffer{};
            if (auto bytes = client->receive(buffer)) {
                std::string message(reinterpret_cast<const char *>(buffer.data()), bytes.value());
                std::cout << "Received string: " << message << std::endl;
                if (auto send_result = client->send(std::span{buffer.data(), bytes.value()}); !send_result.has_value()) {
                    std::cerr << "Error: " << net::error_to_string(bind_result.error()) << '\n';
                }
            }
        }
    }
}