#include <base/signal.h>
#include <terminal_session/terminal_session.h>
#include <os/session_policy.h>
#include <os/ring_buffer.h>
#include <base/attached_rom_dataspace.h>
#include <base/attached_ram_dataspace.h>
#include <root/component.h>
#include <base/component.h>
#include <base/log.h>
#include <util/avl_tree.h>

/* local includes */
#include "tox_node.h"

typedef Tox::uint8_t uint8_t;

namespace Tox_terminal {

	using namespace Terminal;

	class  Session_component;
	struct Session_node;
	class  Root_component;

}


extern "C"
void connection_status_cb(Tox::Tox *tox,
                          Tox::TOX_CONNECTION status,
                          void *arg)
{
	using namespace Tox;

	switch(status) {
	case TOX_CONNECTION_NONE:
		Genode::error("not connected to DHT"); break;
	case TOX_CONNECTION_TCP:
		Genode::warning("TCP relay established"); break;
	case TOX_CONNECTION_UDP:
		Genode::log("UDP connection established"); break;
	}

	tox_self_set_status(tox, TOX_USER_STATUS_NONE);
}

extern "C"
void friend_request_cb(Tox::Tox           *tox,
                       Tox::uint8_t const *public_key,
                       Tox::uint8_t const *message,
                       Tox::size_t         length,
                       void               *arg)
{
	using namespace Tox;

	Genode::log("Friend request accepted from ", (Hex_address)public_key, "\n",
	            Message(message, length));
	/* TODO: check error */
	tox_friend_add_norequest(tox, public_key, NULL);
}

extern "C"
void friend_message_cb(Tox::Tox             *tox,
                       Tox::uint32_t         friend_num,
                       Tox::TOX_MESSAGE_TYPE type,
                       Tox::uint8_t const   *message,
                       Tox::size_t           length,
                       void                 *arg);

extern "C"
void friend_connection_status_cb(Tox::Tox            *tox,
                                 Tox::uint32_t        friend_number,
                                 Tox::TOX_CONNECTION  connection_status,
                                 void                *arg);

class Tox_terminal::Session_component :
	public Genode::Rpc_object<Session, Session_component>
{
	private:

		Tox::Tox *_tox;
		Genode::Attached_ram_dataspace    _io_ds;
		Genode::Ring_buffer<Tox::uint8_t,  TOX_MAX_MESSAGE_LENGTH*2>
		                                  _msg_buf;
		Genode::Signal_context_capability _connected_cap;
		Genode::Signal_context_capability _avail_cap;

	public:

		Genode::uint32_t const friend_num;

		Session_component(Genode::Env      &env,
		                  Genode::size_t    buffer_size,
		                  Tox::Tox         *tox,
		                  Genode::uint32_t  friend_num)
		:
			_tox(tox),
			_io_ds(env.ram(), env.rm(), buffer_size),
			friend_num(friend_num)
		{ }

		void connection_status(Tox::TOX_CONNECTION status)
		{
			if ((status != Tox::TOX_CONNECTION_NONE) && _connected_cap.valid())
				Genode::Signal_transmitter(_connected_cap).submit();
		}

		bool message(Tox::uint8_t const *msg, int len)
		{
			if (_msg_buf.avail_capacity() < len)
				return false;

			for (int i = 0; i < len; ++i)
				_msg_buf.add(msg[i]);

			if (_avail_cap.valid())
				Genode::Signal_transmitter(_avail_cap).submit();

			return true;
		}


		/********************************
		 ** Terminal session interface **
		 ********************************/

		Terminal::Session::Size size() override { return Size(0, 0); }

		bool avail() override { return !_msg_buf.empty(); }

		Genode::size_t _read(Genode::size_t num_bytes)
		{
			num_bytes = Genode::min(num_bytes, _io_ds.size());
			uint8_t *dst = _io_ds.local_addr<uint8_t>();

			Genode::size_t n = 0;
			while (!_msg_buf.empty() && n < num_bytes) {
				*dst = _msg_buf.get();
				++dst;
				++n;
			}
			return n;
		}

		void _write(Genode::size_t num_bytes)
		{
			using namespace Tox;
			TOX_MESSAGE_TYPE const type = TOX_MESSAGE_TYPE_NORMAL;
			TOX_ERR_FRIEND_SEND_MESSAGE err;

			num_bytes = Genode::min(num_bytes, _io_ds.size());
			uint8_t const *buf = _io_ds.local_addr<uint8_t>();
			do {
				size_t n = Genode::min(
					(Genode::size_t)TOX_MAX_MESSAGE_LENGTH, num_bytes);
				tox_friend_send_message(_tox, friend_num, type, buf, n, &err);

				switch(err) {
				case TOX_ERR_FRIEND_SEND_MESSAGE_OK: break;
				case TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED:
					Genode::error("friend not connected"); break;
				case TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND:
					Genode::error("friend not found"); break;
				case TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ:
					Genode::error("send queue allocation failed"); break;
				case TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY:
				case TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG:
				case TOX_ERR_FRIEND_SEND_MESSAGE_NULL:
					Genode::error("internal error while sending message");
					break;
				}

				buf += n;
				num_bytes -= n;
			} while (num_bytes);
		}

		Genode::Dataspace_capability _dataspace() { return _io_ds.cap(); }

		void read_avail_sigh(Genode::Signal_context_capability cap)
		{
			_avail_cap = cap;
		}

		void connected_sigh(Genode::Signal_context_capability cap)
		{
			using namespace Tox;

			_connected_cap = cap;

			if (cap.valid()) {
				TOX_CONNECTION status;
				TOX_ERR_FRIEND_QUERY err;
				status = Tox::tox_friend_get_connection_status(_tox, friend_num, &err);
				if ((err == TOX_ERR_FRIEND_QUERY_OK) && (status != TOX_CONNECTION_NONE))
					Genode::Signal_transmitter(_connected_cap).submit();
			}
		}

		Genode::size_t read(       void*, Genode::size_t) { return 0; }
		Genode::size_t write(const void*, Genode::size_t) { return 0; }

};

struct Tox_terminal::Session_node : Genode::Avl_node<Session_node>
{
	Session_component session;

	Session_node(Genode::Env      &env,
	             Genode::size_t    buffer_size,
	             Tox::Tox         *tox,
	             Genode::uint32_t  friend_num)
	: session(env, buffer_size, tox, friend_num) { }

	/************************
	 ** Avl node interface **
	 ************************/

	bool higher (Session_node *node) const {
		return (node->session.friend_num > session.friend_num); }

	Session_node *lookup_session(Genode::uint32_t  friend_num)
	{
		if (friend_num == session.friend_num) return this;

		Session_node *node = Avl_node<Session_node>::child(
			friend_num > session.friend_num);

		return node ? node->lookup_session(friend_num) : nullptr;
	}
};


class Tox_terminal::Root_component :
	public Genode::Root_component<Session_component>
{
	private:

		Genode::Env &_env;

		Genode::Attached_rom_dataspace _config { _env, "config" };

		Tox::Tox_node _tox { _env, _config.xml() };

		Genode::Avl_tree<Session_node> _session_tree;

	protected:

		Session_component *_create_session(char const *args) override
		{
			using namespace Genode;
			using namespace Tox;

			Session_label const label(args);

			size_t ram_quota   = Arg_string::find_arg(args, "ram_quota").aligned_size();
			size_t buffer_size = Arg_string::find_arg(args, "buf_size").aligned_size();
			if (!buffer_size)
				buffer_size = 4096;

			size_t session_size =
				max((size_t)4096, sizeof(Session_node)) + buffer_size;

			if (session_size > ram_quota) {
				Genode::warning("insufficient quota from ", label.string());
			}

			typedef String<96> Id;
			Id id;
			try {
				Session_policy policy(label, _config.xml());
				id = policy.attribute_value("id", Id());
				if (id == "")
					throw Root::Unavailable();
			} catch (...) {
				error("failed to determine policy for ", label.string());
				throw Root::Unavailable();
			}

			uint8_t bin_id[TOX_ADDRESS_SIZE];
			decode_hex(bin_id, sizeof(bin_id), (uint8_t const*)id.string(), id.length());

			Tox::TOX_ERR_FRIEND_ADD add_err;
			Tox::uint32_t friend_num =
				tox_friend_add(_tox.tox, bin_id, (uint8_t const*)" ", 1, &add_err);

			if (!(add_err == TOX_ERR_FRIEND_ADD_OK) ||
			     (add_err == TOX_ERR_FRIEND_ADD_ALREADY_SENT)) {
				switch(add_err) {
				case TOX_ERR_FRIEND_ADD_NULL:
					Genode::error("TOX_ERR_FRIEND_ADD_NULL"); break;
				case TOX_ERR_FRIEND_ADD_TOO_LONG:
					Genode::error("TOX_ERR_FRIEND_ADD_TOO_LONG"); break;
				case TOX_ERR_FRIEND_ADD_NO_MESSAGE:
					Genode::error("TOX_ERR_FRIEND_ADD_NO_MESSAGE"); break;
				case TOX_ERR_FRIEND_ADD_OWN_KEY:
					Genode::error("TOX_ERR_FRIEND_ADD_OWN_KEY"); break;
				case TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
					Genode::error("TOX_ERR_FRIEND_ADD_BAD_CHECKSUM"); break;
				case TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
					Genode::error("TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM"); break;
				case TOX_ERR_FRIEND_ADD_MALLOC:
					Genode::error("TOX_ERR_FRIEND_ADD_MALLOC"); break;
				case TOX_ERR_FRIEND_ADD_ALREADY_SENT:
				case TOX_ERR_FRIEND_ADD_OK: break;
				}
				throw Root::Unavailable();
			}

			Session_node *node = new (md_alloc())
				Session_node(_env, buffer_size, _tox.tox, friend_num);
			_session_tree.insert(node);

			log("session open from ", label.string(), " to ", id.string());
			return &node->session;
		}

		void _destroy_session(Session_component *session) override
		{
			Session_node *node =
				_session_tree.first()->lookup_session(session->friend_num);
			_session_tree.remove(node);
			destroy(md_alloc(), node);
		}

	public:

		Root_component(Genode::Env &env, Genode::Allocator &md_alloc)
		:
			Genode::Root_component<Session_component>(env.ep(), md_alloc),
			_env(env)
		{

			tox_callback_self_connection_status(
				_tox.tox, connection_status_cb, this);
			tox_callback_friend_connection_status(
				_tox.tox, friend_connection_status_cb, this);
			tox_callback_friend_request( 
				_tox.tox, friend_request_cb, this);
			tox_callback_friend_message(
				_tox.tox, friend_message_cb, this);

			env.parent().announce(env.ep().manage(*this));
		}

		Session_node *lookup_session(Tox::uint32_t friend_num)
		{
			return _session_tree.first()
				? _session_tree.first()->lookup_session(friend_num)
				: nullptr;
		}
};


/***************
 ** Callbacks **
 ***************/

extern "C"
void friend_message_cb(Tox::Tox             *tox,
                       Tox::uint32_t         friend_number,
                       Tox::TOX_MESSAGE_TYPE type,
                       Tox::uint8_t const   *message,
                       Tox::size_t           length,
                       void                 *arg)
{
	using namespace Tox;

	Tox_terminal::Root_component *root =
		(Tox_terminal::Root_component*)arg;
	Tox_terminal::Session_node *node =
		root->lookup_session(friend_number);

	if (node)
		node->session.message(message, length);
}

extern "C"
void friend_connection_status_cb(Tox::Tox            *tox,
                                 Tox::uint32_t        friend_number,
                                 Tox::TOX_CONNECTION  status,
                                 void                *arg)
{
	using namespace Tox;

	Tox_terminal::Root_component *root =
		(Tox_terminal::Root_component*)arg;
	Tox_terminal::Session_node *node =
		root->lookup_session(friend_number);

	if (node)
		node->session.connection_status(status);
}


Genode::size_t Component::stack_size() { return 4*1024*sizeof(long); }

void Component::construct(Genode::Env &env)
{
	static Genode::Sliced_heap   sliced_heap { env.ram(), env.rm() };
	static Tox_terminal::Root_component root { env, sliced_heap    };
}

