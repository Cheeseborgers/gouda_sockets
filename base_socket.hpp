#pragma once

#include <chrono>
#include <expected>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <variant>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t INVALID_SOCKET_VALUE = -1;
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace net {

struct SocketLinger {
    int enabled;           // 0 = off, non-zero = on
    int seconds_to_linger; // seconds to linger

    auto operator<=>(const SocketLinger&) const = default;
};

// Strong type enums for errors and options
enum class SocketError : uint8_t {
    None,
    CreateFailed,
    BindFailed,
    ListenFailed,
    ConnectFailed,
    AcceptFailed,
    SendFailed,
    ReceiveFailed,
    CloseFailed,
    SetOptionFailed,
    GetOptionFailed,
    InvalidAddress,
    InvalidPort,
    Timeout,
    WouldBlock,
    ConnectionReset,
    ConnectionAborted,
    NetworkUnreachable,
    HostUnreachable,
    SslInitFailed,
    SslHandshakeFailed,
    SslReadFailed,
    SslWriteFailed,
    CertificateError,
    Unknown
};

enum class SocketType : uint8_t { Tcp, Udp };

enum class AddressFamily : uint8_t { IPv4 = AF_INET, IPv6 = AF_INET6 };

enum class SocketOption : uint8_t {
    ReuseAddress,
    ReusePort,
    KeepAlive,
    NoDelay,
    Linger,
    ReceiveTimeout,
    SendTimeout,
    ReceiveBufferSize,
    SendBufferSize,
    Broadcast,
    NonBlocking
};

enum class SSLMethod : uint8_t { TLS, TLS_v1_2, TLS_v1_3, DTLS, DTLS_v1_2 };

// Forward declarations
class SocketAddress;
class BaseSocket;
class TCPSocket;
class UDPSocket;
class TCPServerSocket;
class SSLSocket;
class SSLServerSocket;

// Type aliases for expected results
template <typename T>
using SocketResult = std::expected<T, SocketError>;

using VoidSocketResult = SocketResult<void>;

// Socket address abstraction
class SocketAddress {
public:
    SocketAddress() = default;

    static SocketResult<SocketAddress> from_string(const std::string_view address, const uint16_t port,
                                                   const AddressFamily family = AddressFamily::IPv4)
    {
        SocketAddress addr{};
        addr.m_family = family;
        addr.m_port = port;
        addr.m_address = address;

        if (family == AddressFamily::IPv4) {
            addr.storage_.sin_family = AF_INET;
            addr.storage_.sin_port = htons(port);
            if (inet_pton(AF_INET, address.data(), &addr.storage_.sin_addr) != 1) {
                return std::unexpected(SocketError::InvalidAddress);
            }
        }
        else {
            addr.storage_v6_.sin6_family = AF_INET6;
            addr.storage_v6_.sin6_port = htons(port);
            addr.storage_v6_.sin6_flowinfo = 0;
            addr.storage_v6_.sin6_scope_id = 0;

            if (inet_pton(AF_INET6, address.data(), &addr.storage_v6_.sin6_addr) != 1) {
                return std::unexpected(SocketError::InvalidAddress);
            }
        }

        return addr;
    }

    static SocketResult<SocketAddress> any(const uint16_t port, const AddressFamily family = AddressFamily::IPv4)
    {
        return family == AddressFamily::IPv4 ? from_string("0.0.0.0", port, family) : from_string("::", port, family);
    }

    static SocketResult<SocketAddress> loopback(const uint16_t port, const AddressFamily family = AddressFamily::IPv4)
    {
        return family == AddressFamily::IPv4 ? from_string("127.0.0.1", port, family)
                                             : from_string("::1", port, family);
    }

    [[nodiscard]] const sockaddr *get_sockaddr() const
    {
        return m_family == AddressFamily::IPv4 ? reinterpret_cast<const sockaddr *>(&storage_)
                                               : reinterpret_cast<const sockaddr *>(&storage_v6_);
    }

    [[nodiscard]] socklen_t get_socklen() const
    {
        return m_family == AddressFamily::IPv4 ? sizeof(storage_) : sizeof(storage_v6_);
    }

    [[nodiscard]] AddressFamily family() const { return m_family; }
    [[nodiscard]] uint16_t port() const { return m_port; }
    [[nodiscard]] std::string_view address() const { return m_address; }

private:
    AddressFamily m_family = AddressFamily::IPv4;
    uint16_t m_port = 0;
    std::string m_address;

    union {
        sockaddr_in storage_{};
        sockaddr_in6 storage_v6_;
    };
};

// Base socket class with RAII
class BaseSocket {
public:
    BaseSocket() = default;

    explicit BaseSocket(const socket_t sock) : m_socket(sock) {}

    BaseSocket(const BaseSocket &) = delete;
    BaseSocket &operator=(const BaseSocket &) = delete;

    BaseSocket(BaseSocket &&other) noexcept : m_socket(std::exchange(other.m_socket, INVALID_SOCKET_VALUE)) {}

    BaseSocket &operator=(BaseSocket &&other) noexcept
    {
        if (this != &other) {
            close();
            m_socket = std::exchange(other.m_socket, INVALID_SOCKET_VALUE);
        }
        return *this;
    }

    virtual ~BaseSocket() { close(); }

    [[nodiscard]] bool is_valid() const { return m_socket != INVALID_SOCKET_VALUE; }
    [[nodiscard]] socket_t native_handle() const { return m_socket; }

    VoidSocketResult close()
    {
        if (m_socket != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
            if (::closesocket(socket_) != 0) {
                return std::unexpected(SocketError::CloseFailed);
            }
#else
            if (::close(m_socket) != 0) {
                return std::unexpected(SocketError::CloseFailed);
            }
#endif
            m_socket = INVALID_SOCKET_VALUE;
        }
        return {};
    }

    template <typename T>
VoidSocketResult set_option(SocketOption option, const T &value)
    {
        if (option == SocketOption::NonBlocking) {
#ifdef _WIN32
            u_long mode = value ? 1 : 0;
            if (ioctlsocket(m_socket, FIONBIO, &mode) != 0) {
                return std::unexpected(SocketError::SetOptionFailed);
            }
#else
            int flags = fcntl(m_socket, F_GETFL, 0);
            if (flags < 0) {
                return std::unexpected(SocketError::SetOptionFailed);
            }

            if (value) {
                flags |= O_NONBLOCK;
            }
            else {
                flags &= ~O_NONBLOCK;
            }

            if (fcntl(m_socket, F_SETFL, flags) != 0) {
                return std::unexpected(SocketError::SetOptionFailed);
            }
#endif
            return {};
        }

        // Normal flow for other options
        int level{0};
        int name{0};
        const void *val_ptr{nullptr};
        socklen_t val_len{0};

        if (!get_socket_option_params(option, level, name, val_ptr, val_len, value)) {
            return std::unexpected(SocketError::SetOptionFailed);
        }

        if (setsockopt(m_socket, level, name, val_ptr, val_len) != 0) {
            return std::unexpected(SocketError::SetOptionFailed);
        }

        return {};
    }

    template <typename T>
    SocketResult<T> get_option(const SocketOption option) const
    {
        if (option == SocketOption::NonBlocking) {
#ifdef _WIN32
            u_long mode = 0;
            if (ioctlsocket(m_socket, FIONBIO, &mode) != 0) {
                return std::unexpected(SocketError::GetOptionFailed);
            }
            return static_cast<T>(mode != 0);
#else
            const int flags = fcntl(m_socket, F_GETFL, 0);
            if (flags < 0) {
                return std::unexpected(SocketError::GetOptionFailed);
            }
            return static_cast<T>((flags & O_NONBLOCK) != 0);
#endif
        }

        // Normal flow for other options
        int level{0};
        int name{0};
        T value{};
        socklen_t val_len{sizeof(T)};

        if (!get_socket_option_params(option, level, name)) {
            return std::unexpected(SocketError::GetOptionFailed);
        }

        if (getsockopt(m_socket, level, name, reinterpret_cast<char *>(&value), &val_len) != 0) {
            return std::unexpected(SocketError::GetOptionFailed);
        }

        return value;
    }

protected:
    socket_t m_socket{INVALID_SOCKET_VALUE};

    static SocketResult<socket_t> create_socket(const SocketType type, AddressFamily family)
    {
        const int domain{static_cast<int>(family)};
        const int sock_type{type == SocketType::Tcp ? SOCK_STREAM : SOCK_DGRAM};
        const int protocol{type == SocketType::Tcp ? IPPROTO_TCP : IPPROTO_UDP};

        socket_t sock{socket(domain, sock_type, protocol)};
        if (sock == INVALID_SOCKET_VALUE) {
            return std::unexpected(SocketError::CreateFailed);
        }

        return sock;
    }

private:
    template <typename T>
    void assign_sockopt_value(const T &value, const void *&val_ptr, socklen_t &val_len) const
    {
        val_ptr = static_cast<const void *>(std::addressof(value));
        val_len = static_cast<socklen_t>(sizeof(T));
    }

    template <typename T>
bool get_socket_option_params(const SocketOption option, int &level, int &name, const void *&val_ptr,
                              socklen_t &val_len, const T &value) const
    {
        bool handled = false;

        switch (option) {
            case SocketOption::ReuseAddress:
                level = SOL_SOCKET;
                name = SO_REUSEADDR;
                break;
            case SocketOption::ReusePort:
#ifdef SO_REUSEPORT
                level = SOL_SOCKET;
                name = SO_REUSEPORT;
#else
                return false;
#endif
                break;
            case SocketOption::KeepAlive:
                level = SOL_SOCKET;
                name = SO_KEEPALIVE;
                break;
            case SocketOption::NoDelay:
                level = IPPROTO_TCP;
                name = TCP_NODELAY;
                break;
            case SocketOption::ReceiveTimeout:
                level = SOL_SOCKET;
                name = SO_RCVTIMEO;
                break;
            case SocketOption::SendTimeout:
                level = SOL_SOCKET;
                name = SO_SNDTIMEO;
                break;
            case SocketOption::ReceiveBufferSize:
                level = SOL_SOCKET;
                name = SO_RCVBUF;
                break;
            case SocketOption::SendBufferSize:
                level = SOL_SOCKET;
                name = SO_SNDBUF;
                break;
            case SocketOption::Broadcast:
                level = SOL_SOCKET;
                name = SO_BROADCAST;
                break;
            case SocketOption::Linger:
                level = SOL_SOCKET;
                name = SO_LINGER;
                // Manually assign using the correct size of linger struct
                val_ptr = static_cast<const void *>(std::addressof(value));
                val_len = static_cast<socklen_t>(sizeof(linger));
                handled = true;
                break;
            default:
                return false;
        }

        if (!handled) {
            assign_sockopt_value(value, val_ptr, val_len);
        }

        return true;
    }

    bool get_socket_option_params(const SocketOption option, int &level, int &name) const
    {
        switch (option) {
            case SocketOption::ReuseAddress:
                level = SOL_SOCKET;
                name = SO_REUSEADDR;
                break;
            case SocketOption::ReusePort:
#ifdef SO_REUSEPORT
                level = SOL_SOCKET;
                name = SO_REUSEPORT;
                break;
#else
                return false;
#endif
            case SocketOption::KeepAlive:
                level = SOL_SOCKET;
                name = SO_KEEPALIVE;
                break;
            case SocketOption::NoDelay:
                level = IPPROTO_TCP;
                name = TCP_NODELAY;
                break;
            case SocketOption::ReceiveTimeout:
                level = SOL_SOCKET;
                name = SO_RCVTIMEO;
                break;
            case SocketOption::SendTimeout:
                level = SOL_SOCKET;
                name = SO_SNDTIMEO;
                break;
            case SocketOption::ReceiveBufferSize:
                level = SOL_SOCKET;
                name = SO_RCVBUF;
                break;
            case SocketOption::SendBufferSize:
                level = SOL_SOCKET;
                name = SO_SNDBUF;
                break;
            case SocketOption::Broadcast:
                level = SOL_SOCKET;
                name = SO_BROADCAST;
                break;
            case SocketOption::Linger:
                level = SOL_SOCKET;
                name = SO_LINGER;
                break;
            default:
                return false;
        }
        return true;
    }
};

// TCP Socket implementation
class TCPSocket final : public BaseSocket {
public:
    static SocketResult<TCPSocket> create(const AddressFamily family = AddressFamily::IPv4)
    {
        auto sock_result = create_socket(SocketType::Tcp, family);
        if (!sock_result) {
            return std::unexpected(sock_result.error());
        }

        return TCPSocket(sock_result.value());
    }

    static SocketResult<TCPSocket> connect_to(const SocketAddress &address)
    {
        auto socket_result = create(address.family());
        if (!socket_result) {
            return std::unexpected(socket_result.error());
        }

        auto &socket = socket_result.value();
        if (auto connect_result = socket.connect(address); !connect_result) {
            return std::unexpected(connect_result.error());
        }

        return std::move(socket);
    }

    [[nodiscard]] VoidSocketResult bind(const SocketAddress &address) const
    {
        if (::bind(m_socket, address.get_sockaddr(), address.get_socklen()) != 0) {
            return std::unexpected(SocketError::BindFailed);
        }
        return {};
    }

    [[nodiscard]] VoidSocketResult connect(const SocketAddress &address) const
    {
        if (::connect(m_socket, address.get_sockaddr(), address.get_socklen()) != 0) {
            return std::unexpected(SocketError::ConnectFailed);
        }
        return {};
    }

    [[nodiscard]] SocketResult<size_t> send(const std::span<const std::byte> data) const
    {
        const auto result = ::send(m_socket, data.data(), data.size(), 0);
        if (result < 0) {
            return std::unexpected(SocketError::SendFailed);
        }
        return static_cast<size_t>(result);
    }

    [[nodiscard]] SocketResult<size_t> receive(std::span<std::byte> buffer) const
    {
        const auto result = recv(m_socket, buffer.data(), buffer.size(), 0);
        if (result < 0) {
            return std::unexpected(SocketError::ReceiveFailed);
        }
        return static_cast<size_t>(result);
    }

protected:
    explicit TCPSocket(const socket_t sock) : BaseSocket(sock) {}
    friend class TCPServerSocket;
    friend class SSLSocket;
};

// UDP Socket implementation
class UDPSocket final : public BaseSocket {
public:
    static SocketResult<UDPSocket> create(const AddressFamily family = AddressFamily::IPv4)
    {
        auto sock_result = create_socket(SocketType::Udp, family);
        if (!sock_result) {
            return std::unexpected(sock_result.error());
        }

        return UDPSocket(sock_result.value());
    }

    [[nodiscard]] VoidSocketResult bind(const SocketAddress &address) const
    {
        if (::bind(m_socket, address.get_sockaddr(), address.get_socklen()) != 0) {
            return std::unexpected(SocketError::BindFailed);
        }
        return {};
    }

    [[nodiscard]] SocketResult<size_t> send_to(const std::span<const std::byte> data,
                                               const SocketAddress &address) const
    {
        const auto result =
            sendto(m_socket, data.data(), data.size(), 0, address.get_sockaddr(), address.get_socklen());
        if (result < 0) {
            return std::unexpected(SocketError::SendFailed);
        }
        return static_cast<size_t>(result);
    }

    [[nodiscard]] SocketResult<std::pair<size_t, SocketAddress>> receive_from(std::span<std::byte> buffer) const
    {
        sockaddr_storage addr_storage{};
        socklen_t addr_len{sizeof(addr_storage)};

        const auto result =
            recvfrom(m_socket, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr *>(&addr_storage), &addr_len);

        if (result < 0) {
            return std::unexpected(SocketError::ReceiveFailed);
        }

        // Convert sockaddr back to SocketAddress
        SocketResult<SocketAddress> addr{};
        char addr_str[INET6_ADDRSTRLEN]{};
        uint16_t port{0};

        if (addr_storage.ss_family == AF_INET) {
            const auto *s = reinterpret_cast<sockaddr_in *>(&addr_storage);
            inet_ntop(AF_INET, &s->sin_addr, addr_str, sizeof(addr_str));
            port = ntohs(s->sin_port);
            addr = SocketAddress::from_string(addr_str, port, AddressFamily::IPv4);
        }
        else {
            const auto *s6 = reinterpret_cast<sockaddr_in6 *>(&addr_storage);
            inet_ntop(AF_INET6, &s6->sin6_addr, addr_str, sizeof(addr_str));
            port = ntohs(s6->sin6_port);
            addr = SocketAddress::from_string(addr_str, port, AddressFamily::IPv6);
        }

        return std::make_pair(static_cast<size_t>(result), addr.value());
    }

private:
    explicit UDPSocket(const socket_t sock) : BaseSocket(sock) {}
};

// TCP Server implementation
class TCPServerSocket final : public BaseSocket {
public:
    static SocketResult<TCPServerSocket> create(const AddressFamily family = AddressFamily::IPv4)
    {
        auto sock_result = create_socket(SocketType::Tcp, family);
        if (!sock_result) {
            return std::unexpected(sock_result.error());
        }

        return TCPServerSocket(sock_result.value());
    }

    [[nodiscard]] VoidSocketResult bind(const SocketAddress &address) const
    {
        if (::bind(m_socket, address.get_sockaddr(), address.get_socklen()) != 0) {
            return std::unexpected(SocketError::BindFailed);
        }
        return {};
    }

    [[nodiscard]] VoidSocketResult listen(const int backlog = SOMAXCONN) const
    {
        if (::listen(m_socket, backlog) != 0) {
            return std::unexpected(SocketError::ListenFailed);
        }
        return {};
    }

    [[nodiscard]] VoidSocketResult bind_and_listen(const SocketAddress &address, const int backlog = SOMAXCONN) const
    {
        if (auto bind_result = bind(address); !bind_result) {
            return bind_result;
        }

        if (auto listen_result = listen(backlog); !listen_result) {
            return listen_result;
        }

        return {};
    }

    [[nodiscard]] SocketResult<TCPSocket> accept() const
    {
        const socket_t client_sock = ::accept(m_socket, nullptr, nullptr);
        if (client_sock == INVALID_SOCKET_VALUE) {
            return std::unexpected(SocketError::AcceptFailed);
        }

        return TCPSocket{client_sock};
    }

protected:
    explicit TCPServerSocket(const socket_t sock) : BaseSocket(sock) {}
};

// SSL Context RAII wrapper
class SSLContext {
public:
    static SocketResult<SSLContext> create(const SSLMethod method)
    {
        const SSL_METHOD *ssl_method{nullptr};

        switch (method) {
            case SSLMethod::TLS:
            case SSLMethod::TLS_v1_2:
            case SSLMethod::TLS_v1_3:
                ssl_method = TLS_method();
                break;
            default:
                return std::unexpected(SocketError::SslInitFailed);
        }

        SSL_CTX *ctx{SSL_CTX_new(ssl_method)};
        if (!ctx) {
            return std::unexpected(SocketError::SslInitFailed);
        }

        // Restrict protocol versions if needed
        if (method == SSLMethod::TLS_v1_2) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
            SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        }
        else if (method == SSLMethod::TLS_v1_3) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        }

        return SSLContext(ctx);
    }

    ~SSLContext()
    {
        if (p_ssl_ctx) {
            SSL_CTX_free(p_ssl_ctx);
        }
    }

    SSLContext(const SSLContext &) = delete;
    SSLContext &operator=(const SSLContext &) = delete;

    SSLContext(SSLContext &&other) noexcept : p_ssl_ctx(std::exchange(other.p_ssl_ctx, nullptr)) {}

    SSLContext &operator=(SSLContext &&other) noexcept
    {
        if (this != &other) {
            if (p_ssl_ctx)
                SSL_CTX_free(p_ssl_ctx);
            p_ssl_ctx = std::exchange(other.p_ssl_ctx, nullptr);
        }
        return *this;
    }

    [[nodiscard]] VoidSocketResult load_cert_file(const std::string_view cert_file) const
    {
        if (SSL_CTX_use_certificate_file(p_ssl_ctx, cert_file.data(), SSL_FILETYPE_PEM) != 1) {
            return std::unexpected(SocketError::CertificateError);
        }
        return {};
    }

    [[nodiscard]] VoidSocketResult load_private_key_file(const std::string_view key_file) const
    {
        if (SSL_CTX_use_PrivateKey_file(p_ssl_ctx, key_file.data(), SSL_FILETYPE_PEM) != 1) {
            return std::unexpected(SocketError::CertificateError);
        }
        return {};
    }

    [[nodiscard]] SSL_CTX *native_handle() const { return p_ssl_ctx; }

private:
    explicit SSLContext(SSL_CTX *ctx) : p_ssl_ctx(ctx) {}
    SSL_CTX *p_ssl_ctx{nullptr};
};

// SSL Socket implementation
class SSLSocket final : public BaseSocket {
public:
    static SocketResult<SSLSocket> create_client(const SSLContext &context,
                                                 const AddressFamily family = AddressFamily::IPv4)
    {
        auto tcp_result = TCPSocket::create(family);
        if (!tcp_result) {
            return std::unexpected(tcp_result.error());
        }

        SSL *ssl{SSL_new(context.native_handle())};
        if (!ssl) {
            return std::unexpected(SocketError::SslInitFailed);
        }

        return SSLSocket(tcp_result->native_handle(), ssl, false);
    }

    static SocketResult<SSLSocket> create_server(const SSLContext &context, const socket_t accepted_socket)
    {
        SSL *ssl{SSL_new(context.native_handle())};
        if (!ssl) {
            return std::unexpected(SocketError::SslInitFailed);
        }

        return SSLSocket(accepted_socket, ssl, true);
    }

    ~SSLSocket() override
    {
        if (p_ssl_ctx) {
            SSL_shutdown(p_ssl_ctx);
            SSL_free(p_ssl_ctx);
        }
    }

    SSLSocket(const SSLSocket &) = delete;
    SSLSocket &operator=(const SSLSocket &) = delete;

    SSLSocket(SSLSocket &&other) noexcept
        : BaseSocket(std::move(other)),
          p_ssl_ctx(std::exchange(other.p_ssl_ctx, nullptr)),
          m_is_server(other.m_is_server)
    {
    }

    [[nodiscard]] VoidSocketResult connect(const SocketAddress &address) const
    {
        // First connect the underlying socket
        if (::connect(m_socket, address.get_sockaddr(), address.get_socklen()) != 0) {
            return std::unexpected(SocketError::ConnectFailed);
        }

        // Set up SSL
        if (SSL_set_fd(p_ssl_ctx, m_socket) != 1) {
            return std::unexpected(SocketError::SslInitFailed);
        }

        // Perform SSL handshake
        if (SSL_connect(p_ssl_ctx) != 1) {
            return std::unexpected(SocketError::SslHandshakeFailed);
        }

        return {};
    }

    [[nodiscard]] VoidSocketResult accept_ssl() const
    {
        if (SSL_set_fd(p_ssl_ctx, m_socket) != 1) {
            return std::unexpected(SocketError::SslInitFailed);
        }

        if (SSL_accept(p_ssl_ctx) != 1) {
            return std::unexpected(SocketError::SslHandshakeFailed);
        }

        return {};
    }

    [[nodiscard]] SocketResult<size_t> send(const std::span<const std::byte> data) const
    {
        const int result{SSL_write(p_ssl_ctx, data.data(), static_cast<int>(data.size()))};
        if (result <= 0) {
            return std::unexpected(SocketError::SslWriteFailed);
        }
        return static_cast<size_t>(result);
    }

    [[nodiscard]] SocketResult<size_t> receive(std::span<std::byte> buffer) const
    {
        const int result{SSL_read(p_ssl_ctx, buffer.data(), static_cast<int>(buffer.size()))};
        if (result <= 0) {
            return std::unexpected(SocketError::SslReadFailed);
        }
        return static_cast<size_t>(result);
    }

private:
    SSLSocket(const socket_t sock, SSL *ssl, const bool is_server)
        : BaseSocket(sock), p_ssl_ctx(ssl), m_is_server(is_server)
    {
    }

    SSL *p_ssl_ctx{nullptr};
    bool m_is_server{false};
};

// SSL Server implementation
class SSLServerSocket final : public BaseSocket {
public:
    static SocketResult<SSLServerSocket> create(const SSLContext &context,
                                                const AddressFamily family = AddressFamily::IPv4)
    {
        auto sock_result = create_socket(SocketType::Tcp, family);
        if (!sock_result) {
            return std::unexpected(sock_result.error());
        }

        return SSLServerSocket(sock_result.value(), context);
    }

    [[nodiscard]] VoidSocketResult bind(const SocketAddress &address) const
    {
        if (::bind(m_socket, address.get_sockaddr(), address.get_socklen()) != 0) {
            return std::unexpected(SocketError::BindFailed);
        }
        return {};
    }

    [[nodiscard]] VoidSocketResult listen(const int backlog = SOMAXCONN) const
    {
        if (::listen(m_socket, backlog) != 0) {
            return std::unexpected(SocketError::ListenFailed);
        }
        return {};
    }

    [[nodiscard]] SocketResult<SSLSocket> accept_ssl() const
    {
        const socket_t client_sock{accept(m_socket, nullptr, nullptr)};
        if (client_sock == INVALID_SOCKET_VALUE) {
            return std::unexpected(SocketError::AcceptFailed);
        }

        auto ssl_result = SSLSocket::create_server(m_ssl_context, client_sock);
        if (!ssl_result) {
            return std::unexpected(ssl_result.error());
        }

        if (auto handshake_result = ssl_result->accept_ssl(); !handshake_result) {
            return std::unexpected(handshake_result.error());
        }

        return std::move(ssl_result.value());
    }

private:
    SSLServerSocket(const socket_t sock, const SSLContext &context) : m_ssl_context(context)
    {
        m_socket = sock; // Initialize the socket from TcpServer
    }

    const SSLContext &m_ssl_context;
};

// Error handling utilities
inline std::string_view error_to_string(const SocketError error)
{
    switch (error) {
        case SocketError::None:
            return "No error";
        case SocketError::CreateFailed:
            return "Failed to create socket";
        case SocketError::BindFailed:
            return "Failed to bind socket";
        case SocketError::ListenFailed:
            return "Failed to listen on socket";
        case SocketError::ConnectFailed:
            return "Failed to connect socket";
        case SocketError::AcceptFailed:
            return "Failed to accept connection";
        case SocketError::SendFailed:
            return "Failed to send data";
        case SocketError::ReceiveFailed:
            return "Failed to receive data";
        case SocketError::CloseFailed:
            return "Failed to close socket";
        case SocketError::SetOptionFailed:
            return "Failed to set socket option";
        case SocketError::GetOptionFailed:
            return "Failed to get socket option";
        case SocketError::InvalidAddress:
            return "Invalid address";
        case SocketError::InvalidPort:
            return "Invalid port";
        case SocketError::Timeout:
            return "Operation timed out";
        case SocketError::WouldBlock:
            return "Operation would block";
        case SocketError::ConnectionReset:
            return "Connection reset by peer";
        case SocketError::ConnectionAborted:
            return "Connection aborted";
        case SocketError::NetworkUnreachable:
            return "Network unreachable";
        case SocketError::HostUnreachable:
            return "Host unreachable";
        case SocketError::SslInitFailed:
            return "SSL initialization failed";
        case SocketError::SslHandshakeFailed:
            return "SSL handshake failed";
        case SocketError::SslReadFailed:
            return "SSL read failed";
        case SocketError::SslWriteFailed:
            return "SSL write failed";
        case SocketError::CertificateError:
            return "Certificate error";
        case SocketError::Unknown:
            return "Unknown error";
        default:
            return "Unrecognized error";
    }
}

} // namespace net