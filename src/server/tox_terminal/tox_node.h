#ifndef __TOX_TERMINAL__TOX_NODE_H_
#define __TOX_TERMINAL__TOX_NODE_H_

#include <report_session/connection.h>
#include <timer_session/connection.h>
#include <base/log.h>
#include <util/xml_node.h>

namespace Tox {
#include <toxcore/tox.h>

	class Tox_node;

	static void decode_hex(uint8_t       *bin, unsigned bin_len,
	                       uint8_t const *hex, unsigned hex_len)
	{
		static uint8_t const table[255] = {
			 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
			 0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			 0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		};

		if (bin_len < (hex_len/2))
			bin_len = hex_len/2;

		for (int i = bin_len-1, j = 2*bin_len; i >= 0; --i) {
			bin[i] = table[hex[--j]];
			bin[i] |= ((table[hex[--j]]) << 4);
		}
	}

	template <unsigned N>
	struct Hex
	{
		uint8_t const *bin;

		Hex(uint8_t const *bin) : bin(bin) { }

		void print(Genode::Output &output) const
		{
			static char const alph[0x10] = {
				'0','1','2','3','4','5','6','7',
				'8','9','A','B','C','D','E','F'
			};

			for (unsigned i = 0; i < N; ++i) {
				output.out_char(alph[bin[i] >> 4]);
				output.out_char(alph[bin[i] & 0x0F]);
			}
		}
	};

	typedef Hex<TOX_ADDRESS_SIZE>    Hex_address;
	typedef Hex<TOX_SECRET_KEY_SIZE> Hex_secret_key;

	struct Message
	{
		Genode::uint8_t const *msg;
		Genode::size_t  const  len;

		Message(uint8_t const *message, size_t length)
		: msg(message), len(length) { }

		void print(Genode::Output &output) const
		{
			/* message may contain nulls */
			for (Genode::size_t i = 0; i < len; ++i)
				output.out_char(msg[i]);
		}
	};
}

int errno;
int ENOSYS = 1;
int ENOMEM = 2;
int EINVAL = 3;
int EFBIG  = 4;


/*
void load_rom(Genode::Env &env, Tox::Messenger *msgr)
{
	try {
		Genode::Attached_rom_dataspace ds(env, "tox_data");
		Tox::messenger_load(msgr, ds.local_addr<uint8_t>(), ds.size());
	} catch (...) {
		Genode::error("failed to load data");
	}
}

void save_report(Genode::Env &env, Tox::Messenger *msgr)
{
	try {
		Report::Connection report(env, "tox_data", Tox::messenger_size(msgr));
		Genode::Attached_dataspace ds(env.rm(), report.dataspace());
		Tox::messenger_save(msgr, ds.local_addr<uint8_t>());
	} catch (...) {
		Genode::error("failed to save data");
	}
}
*/


class Tox::Tox_node
{
	public:

		::Tox::Tox *tox;

	private:

		Genode::Env &_env;

		Timer::Connection _timer { _env };
		uint32_t _loop_ms = 50;

		void _iterate()
		{
			tox_iterate(tox);
			uint32_t want_ms = tox_iteration_interval(tox);
			if (want_ms != _loop_ms) {
				Genode::warning("change loop iteration from ", _loop_ms, "ms to ", want_ms, "ms");
				_loop_ms = want_ms;
				_timer.trigger_periodic(_loop_ms * 1000);
			}
		}

		Genode::Signal_handler<Tox_node> _loop_handler
			{ _env.ep(), *this, &Tox_node::_iterate };

	public:

		Tox_node(Genode::Env &env, Genode::Xml_node config)
		: _env(env)
		{
			using namespace Tox;

			Tox_Options options;
			tox_options_default(&options);
			options.ipv6_enabled = false;

			TOX_ERR_NEW err_new;

			if (config.has_attribute("secret_key")) {
				typedef Genode::String<77> Hex_key;
				Hex_key secret_hex = config.attribute_value("secret_key", Hex_key());
				uint8_t secret_key[TOX_SECRET_KEY_SIZE];
				decode_hex(secret_key, sizeof(secret_key),
				           (uint8_t const*)secret_hex.string(), secret_hex.length());

				options.savedata_type = TOX_SAVEDATA_TYPE_SECRET_KEY;
				options.savedata_data = secret_key;
				options.savedata_length = TOX_SECRET_KEY_SIZE;
				tox = tox_new(&options, &err_new);

			} else if (config.attribute_value("ephemeral", false)) {

				options.savedata_type = TOX_SAVEDATA_TYPE_NONE;
				tox = tox_new(&options, &err_new);
				/* print the key so it can be reused in a config */
				if (tox && config.attribute_value("print_key", false)) {
					uint8_t secret_key[TOX_SECRET_KEY_SIZE];
					tox_self_get_secret_key(tox, secret_key);
					Genode::log("secret key: ", (Hex_secret_key)secret_key);
				}

			} else {

				Genode::Attached_rom_dataspace data(env, "data.tox");
				options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
				options.savedata_data = data.local_addr<uint8_t>();
				options.savedata_length = data.size();
				tox = tox_new(&options, &err_new);

			}
			
			if ((!tox) || (err_new != TOX_ERR_NEW_OK)) {
				switch (err_new) {
				case               TOX_ERR_NEW_NULL:
					Genode::error("TOX_ERR_NEW_NULL"); break;
				case               TOX_ERR_NEW_MALLOC:
					Genode::error("TOX_ERR_NEW_MALLOC"); break;
				case               TOX_ERR_NEW_PORT_ALLOC:
					Genode::error("TOX_ERR_NEW_PORT_ALLOC"); break;
				case               TOX_ERR_NEW_PROXY_BAD_TYPE:
					Genode::error("TOX_ERR_NEW_PROXY_BAD_TYPE"); break;
				case               TOX_ERR_NEW_PROXY_BAD_HOST:
					Genode::error("TOX_ERR_NEW_PROXY_BAD_HOST"); break;
				case               TOX_ERR_NEW_PROXY_BAD_PORT:
					Genode::error("TOX_ERR_NEW_PROXY_BAD_PORT"); break;
				case               TOX_ERR_NEW_PROXY_NOT_FOUND:
					Genode::error("TOX_ERR_NEW_PROXY_NOT_FOUND"); break;
				case               TOX_ERR_NEW_LOAD_ENCRYPTED:
					Genode::error("TOX_ERR_NEW_LOAD_ENCRYPTED"); break;
				case               TOX_ERR_NEW_LOAD_BAD_FORMAT:
					Genode::error("TOX_ERR_NEW_LOAD_BAD_FORMAT"); break;
				case TOX_ERR_NEW_OK: break;
				}
				throw err_new;
			}

			if (config.has_attribute("name")) {
				uint8_t buf[TOX_MAX_NAME_LENGTH];
				config.attribute("name").value((char*)buf, sizeof(buf));
				TOX_ERR_SET_INFO err_set_info;
				if (!tox_self_set_name(tox, buf, Genode::strlen((char*)buf), &err_set_info)) {
					Genode::error("failed to set nickname");
				}
			}

			if (config.has_attribute("status")) {
				uint8_t buf[TOX_MAX_STATUS_MESSAGE_LENGTH];
				config.attribute("status").value((char*)buf, sizeof(buf));
				TOX_ERR_SET_INFO err_set_info;
				if (!tox_self_set_status_message(tox, buf, Genode::strlen((char*)buf), &err_set_info)) {
					Genode::error("failed to set status");
				}
			}

			_timer.msleep(4000);

			config.for_each_sub_node("bootstrap", [&] (Genode::Xml_node node) {
				Genode::String<64> host;
				Genode::String<TOX_PUBLIC_KEY_SIZE*2+1> key_hex;
				uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
				unsigned long port = 33445;

				try {
					node.attribute("host").value(&host);
					port = node.attribute_value("port", port);
					node.attribute("public_key").value(&key_hex);
				} catch (...) {
					char buf[node.size()+1];
					Genode::strncpy(buf, node.addr(), sizeof(buf));
					Genode::error("bad bootstrap node ", (char*)buf);
					return;
				}

				decode_hex(public_key, sizeof(public_key),
				           (uint8_t*)key_hex.string(), key_hex.length());

				TOX_ERR_BOOTSTRAP err_bootstrap;
				if (!tox_bootstrap(tox, host.string(), port, public_key, &err_bootstrap)) {
					switch (err_bootstrap) {
					case TOX_ERR_BOOTSTRAP_BAD_HOST:
						Genode::error("bad host for bootstrap node ", host.string(), ":", port); break;
					case TOX_ERR_BOOTSTRAP_BAD_PORT:
						Genode::error("bad port for bootstrap node ", host.string(), ":", port); break;
					case TOX_ERR_BOOTSTRAP_NULL: break;
					case TOX_ERR_BOOTSTRAP_OK:   break;
					}
				}
			});

			{
				uint8_t address[TOX_ADDRESS_SIZE];
				tox_self_get_address(tox, address);
				Genode::log("address: ", (Hex_address)address);
			}

			/* start the event loop */
			_timer.sigh(_loop_handler);
			_timer.trigger_periodic(_loop_ms * 1000);
		}

		~Tox_node()
		{
			tox_kill(tox);
		}
};

#endif