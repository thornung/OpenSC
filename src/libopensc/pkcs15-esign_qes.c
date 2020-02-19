/**
 * PKCS15 emulation layer for GuD cards with eSign and QES application
 *
 * Copyright (C) 2019, Jozsef Dojcsak
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "log.h"
#include "pkcs15.h"
#include "cards.h"
#include <stdlib.h>
#include <string.h>

#define RANDOM_UID_INDICATOR 0x08

static const char name_ESIGN[] = "eSIGN";
static const char name_GuD[] = "GuD";

static const char EF_ODF[] = "5031";

static const unsigned char aid_CIA_ESIGN[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0x00, 0x00, 0x02, 0x45, 0x53, 0x69, 0x67, 0x6E};
static const unsigned char aid_CIA_QES[]   = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x76, 0x00, 0x00, 0x66, 0x01};

typedef struct cdata_st {
	const char *label;
	int	    authority;
	const char *path;
	const char *id;
	int         obj_flags;
} cdata, *pcdata;

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	unsigned int storedlen;
	int         flags;	
	int         tries_left;
	const char  pad_char;
	int         obj_flags;
} pindata, *ppindata; 

typedef struct prdata_st {
	const char *id;
	const char *label;
	unsigned int modulus_len;
	int         usage;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
} prdata, *pprdata;

typedef struct container_st {
	const char *id;
	const pcdata certdata;
	const ppindata pindata;
	const pprdata prdata;
} container;

#define USAGE_NONREP	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
#define USAGE_KE	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_AUT	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP  | \
			SC_PKCS15_PRKEY_USAGE_SIGN

static int get_cert_size(sc_card_t * card, sc_path_t * path, size_t * psize) {
	int r;
	sc_file_t * file;

	r = sc_select_file(card, path, &file);
	LOG_TEST_RET(card->ctx, r, "Failed to select EF certificate");

	*psize = file->size;
	sc_file_free(file);

	sc_log(card->ctx, "Certificate size: %ld", file->size);

	return SC_SUCCESS;
}

static int add_app(sc_pkcs15_card_t *p15card, const container * containers, int container_count) {
	int i, r, containers_added = 0;
	ppindata installed_pins[2];
	int installed_pin_count = 0;
	sc_card_t * card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	//static_assert(p15card == NULL, "P15card value is not set");
	//static_assert(card == NULL, "Card value is not set");

	for( i=0; i < container_count; i++ ) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object    cert_obj;
		size_t cert_size;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));

		sc_pkcs15_format_id(containers[i].id, &cert_info.id);
		cert_info.authority = containers[i].certdata->authority;
		sc_format_path(containers[i].certdata->path, &cert_info.path);

		if ( get_cert_size(card, &cert_info.path, &cert_size) != SC_SUCCESS ) {
			sc_log(card->ctx, "Failed to determine certificate %s size", containers[i].certdata->path);
			continue;
		}

		strlcpy(cert_obj.label, containers[i].certdata->label, sizeof(cert_obj.label));
		cert_obj.flags = containers[i].certdata->obj_flags;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r != SC_SUCCESS) {
			LOG_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "Failed to add emu certificate");
		}

		if (containers[i].pindata != 0) {
			int j;
			int is_pin_installed = 0;
			for (j = 0; j < installed_pin_count; j++) {
				if (installed_pins[j] == containers[i].pindata) {
					is_pin_installed = 1;
					break;
				}
			}

			if (!is_pin_installed) {
				struct sc_pkcs15_auth_info pin_info;
				struct sc_pkcs15_object   pin_obj;

				if ( installed_pin_count < (int)(sizeof(installed_pins)/sizeof(ppindata)) ) {
					installed_pins[installed_pin_count++] = containers[i].pindata;
				} else {
					sc_log(card->ctx, "Warning: using more pins than expected (2).");
				}

				memset(&pin_info, 0, sizeof(pin_info));
				memset(&pin_obj, 0, sizeof(pin_obj));

				sc_pkcs15_format_id(containers[i].pindata->id, &pin_info.auth_id);
				pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
				pin_info.attrs.pin.reference = containers[i].pindata->ref;
				pin_info.attrs.pin.flags = containers[i].pindata->flags;
				pin_info.attrs.pin.type = containers[i].pindata->type;
				pin_info.attrs.pin.min_length = containers[i].pindata->minlen;
				pin_info.attrs.pin.stored_length = containers[i].pindata->storedlen;
				pin_info.attrs.pin.max_length = containers[i].pindata->maxlen;
				pin_info.attrs.pin.pad_char = containers[i].pindata->pad_char;
				if (containers[i].pindata->path != NULL) sc_format_path(containers[i].pindata->path, &pin_info.path);
				pin_info.tries_left = -1;

				strlcpy(pin_obj.label, containers[i].pindata->label, sizeof(pin_obj.label));
				pin_obj.flags = containers[i].pindata->obj_flags;

				r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
				if (r != SC_SUCCESS) {
					LOG_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "Failed to add emu pin");
				}
			}
		}

		if (containers[i].prdata != 0) {
			struct sc_pkcs15_prkey_info prkey_info;
			struct sc_pkcs15_object     prkey_obj;
			int modulus_len = containers[i].prdata->modulus_len;
			memset(&prkey_info, 0, sizeof(prkey_info));
			memset(&prkey_obj, 0, sizeof(prkey_obj));

			sc_pkcs15_format_id(containers[i].id, &prkey_info.id);
			prkey_info.usage = containers[i].prdata->usage;
			prkey_info.native = 1;
			prkey_info.key_reference = containers[i].prdata->ref;
			prkey_info.modulus_length = modulus_len;
			sc_format_path(containers[i].prdata->path, &prkey_info.path);

			strlcpy(prkey_obj.label, containers[i].prdata->label, sizeof(prkey_obj.label));
			prkey_obj.flags = containers[i].prdata->obj_flags;
			if (containers[i].prdata->auth_id) {
				sc_pkcs15_format_id(containers[i].prdata->auth_id, &prkey_obj.auth_id);
			}

			r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
			if (r < 0) {
				LOG_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "Failed to add emu pin");
			}
		}

		containers_added++;
	}
	
	if ( containers_added == 0 ) {
		return SC_ERROR_FILE_NOT_FOUND;
	}

	return SC_SUCCESS;
}


static int starcos_add_esign_app(sc_pkcs15_card_t *p15card) {
	static cdata auth_cert = { "C.CH.AUT", 0, "3F00060843F1", "1", 0 };
	static cdata encr_cert = { "C.CH.ENC", 0, "3F0006084301", "2", 0 };

	static prdata auth_key = { "1", "PrK.CH.AUT", 2048, USAGE_AUT, "3F000608", 0x81, "1", SC_PKCS15_CO_FLAG_PRIVATE };
	static prdata encr_key = { "2", "PrK.CH.ENC", 2048, USAGE_KE, "3F000608", 0x83, "1", SC_PKCS15_CO_FLAG_PRIVATE };

	static pindata auth_pin = { "1", "Auth.PIN", "3F00", 0x01, SC_PKCS15_PIN_TYPE_UTF8, 16, 6, 0,
		SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE,
		-1, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE };

	static pindata auth_pin_v35 = { "1", "Auth.PIN", "3F00", 0x06, SC_PKCS15_PIN_TYPE_UTF8, 16, 6, 0,
		SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE,
		-1, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE };
	
	ppindata auth = &auth_pin;
	if ( p15card->card->type == SC_CARD_TYPE_STARCOS_V3_5 ) {
		auth = &auth_pin_v35;
	}
	const container containers[] = {
		{ "1", &auth_cert, auth, &auth_key },
		//Note: the encryption container may not be present on all cards
		{ "2", &encr_cert, auth, &encr_key },
	};

	return add_app(p15card, containers, sizeof(containers)/sizeof(container));
}

static int starcos_add_qes_app(sc_pkcs15_card_t *p15card) {
	static cdata sign_cert = { "C.CH.QES", 0, "3F0006044301", "3", 0 };
	static prdata sign_key = { "3", "PrK.CH.QES", 2048, SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION, "3F000604", 0x84, "2", SC_PKCS15_CO_FLAG_PRIVATE };
	static prdata sign_key_v35 = { "3", "PrK.CH.QES", 3072, SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION, "3F000604", 0x84, "2", SC_PKCS15_CO_FLAG_PRIVATE };
	static pindata sign_pin = { "2", "Sign.PIN", "3F000604", 0x81,  SC_PKCS15_PIN_TYPE_UTF8, 16, 6, 0,
		SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_CONFIDENTIALITY_PROTECTED | SC_PKCS15_PIN_FLAG_LOCAL,
		-1, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE };

	const container containers[] = {
		//Note: the signature container may not be present on all cards
		{ "3", &sign_cert, &sign_pin, (p15card->card->type == SC_CARD_TYPE_STARCOS_V3_5 ? &sign_key_v35 : &sign_key) },
	};

	return add_app(p15card, containers, sizeof(containers)/sizeof(container));
}

static int starcos_esign_qes_init(sc_pkcs15_card_t *p15card, struct sc_aid *aid) {
	sc_context_t * ctx;
	sc_card_t * card;
    int r, apps_added;

    if (!p15card || ! p15card->card || !p15card->card->ctx ) return SC_ERROR_INVALID_ARGUMENTS;

	// convenience variables
	card = p15card->card;
	ctx = card->ctx;
	
    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);

	if (card->type!=SC_CARD_TYPE_STARCOS_V3_4 && card->type!=SC_CARD_TYPE_STARCOS_V3_5) return SC_ERROR_WRONG_CARD;

	apps_added = 0;
	r = starcos_add_esign_app(p15card);
	if ( r == SC_SUCCESS ) apps_added++;

	r = starcos_add_qes_app(p15card);
	if ( r == SC_SUCCESS ) apps_added++;

	if ( apps_added == 0 ) {
		LOG_TEST_RET(ctx, SC_ERROR_WRONG_CARD, "Neither ESign nor QES app");
	}

    if (p15card->tokeninfo) {
		sc_pkcs15_free_tokeninfo(p15card->tokeninfo);
	}

    p15card->tokeninfo = sc_pkcs15_tokeninfo_new();
    if (!p15card->tokeninfo) {
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "unable to create tokeninfo struct");
	} else {
        sc_serial_number_t serial;
		char serial_hex[SC_MAX_SERIALNR*2+2];
	    r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
		LOG_TEST_RET(ctx, r, "Failed to query card serial number");

		sc_bin_to_hex(serial.value, serial.len , serial_hex, sizeof serial_hex, 0);
		p15card->tokeninfo->serial_number = strdup(serial_hex);
		p15card->tokeninfo->label = strdup(name_ESIGN);
		p15card->tokeninfo->manufacturer_id = strdup(name_GuD);
	}

    return SC_SUCCESS;
}

static int fix_and_cache_file(sc_pkcs15_card_t *p15card, const sc_path_t * path, const char * file_name) {
	int r;
	u8 * buf = NULL;
	size_t len;
	sc_path_t tmppath;
	sc_file_t * file;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_NORMAL);

	r = sc_select_file(p15card->card, path, NULL);
	if (r != SC_SUCCESS)   {
		return SC_ERROR_WRONG_CARD;
	}

	sc_format_path(file_name, &tmppath);
	r = sc_select_file(p15card->card, &tmppath, &file);
	if (r != SC_SUCCESS)   {
		return SC_ERROR_UNKNOWN;
	}

	len = file->size;
	buf = malloc(len);
	if(buf == NULL) {
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	r = sc_read_binary(p15card->card, 0, buf, len, 0);
	if (r < SC_SUCCESS)   {
		r = SC_ERROR_UNKNOWN;
	} else {
		len = r;
		r = sc_pkcs15_make_absolute_path(path, &tmppath);
		if ( r == SC_SUCCESS ) {
			const u8 * sequence_wrapper;
			size_t cb_sequence_wrapper;

			sequence_wrapper = sc_asn1_verify_tag(p15card->card->ctx, buf, len, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, &cb_sequence_wrapper);
			if (sequence_wrapper != NULL) {
				sc_pkcs15_cache_file(p15card, &tmppath, sequence_wrapper, cb_sequence_wrapper);
			} else {
				sc_pkcs15_cache_file(p15card, &tmppath, buf, len);
			}
		}
	}

	if ( buf != NULL ) free(buf);
	sc_file_free(file);

	return r;
}

static int fix_and_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df) {
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char *buf;
	const unsigned char *p;
	size_t bufsize;
	size_t len;
	int r;
	struct sc_pkcs15_object *obj = NULL;
	int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *, const u8 **nbuf, size_t *nbufsize) = NULL;

	sc_log(ctx, "called; path=%s, type=%d, enum=%d", sc_print_path(&df->path), df->type, df->enumerated);

	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_decode_prkdf_entry;
		break;
	case SC_PKCS15_PUKDF:
		func = sc_pkcs15_decode_pukdf_entry;
		break;
	case SC_PKCS15_CDF:
	case SC_PKCS15_CDF_TRUSTED:
	case SC_PKCS15_CDF_USEFUL:
		func = sc_pkcs15_decode_cdf_entry;
		break;
	case SC_PKCS15_AODF:
		func = sc_pkcs15_decode_aodf_entry;
		break;
	}
	if (func == NULL) {
		sc_log(ctx, "unknown DF type: %d", df->type);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	r = sc_pkcs15_read_file(p15card, &df->path, &buf, &bufsize);
	LOG_TEST_RET(ctx, r, "pkcs15 read file failed");

	p = sc_asn1_verify_tag(p15card->card->ctx, buf, bufsize, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, &len);
	if ( p == NULL || bufsize - len > 4 ) {
		sc_log(ctx, "Using original DF data %d: %ld (%ld)", df->type, bufsize, len);
		p = buf;
		len = bufsize;
	}

	while (len && *p != 0x00) {
		obj = calloc(1, sizeof(struct sc_pkcs15_object));
		if (obj == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto ret;
		}
		r = func(p15card, obj, &p, &len);
		if (r) {
			free(obj);
			if (r == SC_ERROR_ASN1_END_OF_CONTENTS) {
				r = 0;
				break;
			}
			sc_log(ctx, "%s: Error decoding DF entry", sc_strerror(r));
			goto ret;
		}

		// fix path
		if ( df->type == SC_PKCS15_PRKDF ) {
			struct sc_pkcs15_prkey_info *prkey = (struct sc_pkcs15_prkey_info *) obj->data;
			prkey->key_reference |= 0x80;
		}

		obj->df = df;
		r = sc_pkcs15_add_object(p15card, obj);
		if (r) {
			if (obj->data)
				free(obj->data);
			free(obj);
			sc_log(ctx, "%s: Error adding object", sc_strerror(r));
			goto ret;
		}
	};

	if (r > 0)
		r = 0;
ret:
	df->enumerated = 1; //FIXME: OK?
	free(buf);
	LOG_FUNC_RETURN(ctx, r);
}


static int sc_pkcs15emu_fix_cia_esign_init(sc_pkcs15_card_t *p15card) {
	sc_context_t * ctx;
	sc_card_t * card;

	struct sc_aid parsed_cia_dfs[2];

	int save_use_file_cache;
    int r, apps_added;
	size_t ii;

	// convenience variables
	card = p15card->card;
	ctx = card->ctx;

	// emulator supported applications
	parsed_cia_dfs[0].len = MIN(sizeof(parsed_cia_dfs[0].value), sizeof(aid_CIA_ESIGN));
	memcpy(parsed_cia_dfs[0].value, aid_CIA_ESIGN, parsed_cia_dfs[0].len);
	parsed_cia_dfs[1].len = MIN(sizeof(parsed_cia_dfs[1].value), sizeof(aid_CIA_QES));
	memcpy(parsed_cia_dfs[1].value, aid_CIA_QES, parsed_cia_dfs[1].len);

    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);

	if (card->app_count < 0) {
		r = sc_enum_apps(card);
		LOG_TEST_RET(ctx, r, "unable to enumerate apps");
	}

#ifdef USE_CARD_UID
	if ( card->uid.len == 0 || card->uid.value[0] == RANDOM_UID_INDICATOR ) {
		// reading card UID, needed for caching
		u8 iccsn[16];
		u8 * iccsn_value = iccsn;
		size_t iccsn_len = sizeof(iccsn);
		r = sc_parse_ef_gdo(card, iccsn, &iccsn_len, NULL, NULL);
		if ( r == SC_SUCCESS ) {
			size_t actual_len;
			if ( iccsn_len > 8 ) {
				// we need the last 8 octets for the GUID
				iccsn_value = iccsn + (iccsn_len-8);
				iccsn_len = 8;
			}
			actual_len = MIN(sizeof(card->uid.value), iccsn_len);
			memcpy(card->uid.value, iccsn_value, actual_len);
			card->uid.len = actual_len;
		}
	}
#else
    if ( p15card->tokeninfo == NULL || p15card->tokeninfo->serial_number == NULL ) {
        sc_serial_number_t serial;
		char serial_hex[SC_MAX_SERIALNR*2+2];

        p15card->tokeninfo = sc_pkcs15_tokeninfo_new();
        if (p15card->tokeninfo == NULL) {
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "unable to create tokeninfo struct");
		}

		r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
		LOG_TEST_RET(ctx, r, "Failed to get card serial number");
		sc_bin_to_hex(serial.value, serial.len , serial_hex, sizeof serial_hex, 0);
		p15card->tokeninfo->serial_number = strdup(serial_hex);
		sc_log(ctx, "determined card serial number: '%s'", serial_hex);
    }
#endif

	// trickery: fix and cache broken pkcs15 structures
	save_use_file_cache = p15card->opts.use_file_cache;
	p15card->opts.use_file_cache = 1;

	apps_added = 0;
	r = SC_ERROR_WRONG_CARD;
	for(ii = 0; ii < sizeof(parsed_cia_dfs)/sizeof(struct sc_aid); ii++) {
		const sc_app_info_t * info = sc_find_app(card, &parsed_cia_dfs[ii]);
		
		if (info == NULL || info->path.len == 0) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Cannot find required CIA DF");
			continue;
		}

		sc_log(ctx, "parsing application '%s'", sc_print_path(&info->path));

		r = sc_select_file(card, &info->path, NULL);
		if ( r != SC_SUCCESS ) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Failed select CIA DF");
			continue;
		}

		r = fix_and_cache_file(p15card, &info->path, EF_ODF);
		if ( r != SC_SUCCESS ) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Failed to fix and cache app's EF(ODF)");
		}

		r = sc_pkcs15_bind_internal(p15card, &parsed_cia_dfs[ii]);

		if ( r == SC_SUCCESS ) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "PKCS15 binding OK, proceed with adding DFs");
			struct sc_pkcs15_df	*df = NULL;
			unsigned int	df_mask = 0;
			df_mask |= (1 << SC_PKCS15_PRKDF);
			df_mask |= (1 << SC_PKCS15_PUKDF);
			df_mask |= (1 << SC_PKCS15_CDF);
			df_mask |= (1 << SC_PKCS15_AODF);

			for (df = p15card->df_list; df != NULL; df = df->next) {
				if (!(df_mask & (1 << df->type))) continue;
				fix_and_parse_df(p15card, df);
			}
			apps_added++;

		} else {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Failed to bind PKCS15");
		}

		sc_file_free(p15card->file_odf);
		p15card->file_odf = NULL;
	}

	p15card->opts.use_file_cache = save_use_file_cache;
	sc_log(ctx, "%d CIA apps added successfully", apps_added);
	if ( apps_added > 0 ) {
		r = SC_SUCCESS;
	} else {
		r = SC_ERROR_WRONG_CARD;
	}

    return r;
}

int sc_pkcs15emu_esign_qes_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid) {
	int r = SC_ERROR_WRONG_CARD;

    if (!p15card || ! p15card->card || !p15card->card->ctx) return SC_ERROR_INVALID_ARGUMENTS;

	// card type independent emu
	r = sc_pkcs15emu_fix_cia_esign_init(p15card);
	sc_log(p15card->card->ctx, "Esign/QES CIA init returned: %d", r);
	if ( r != SC_SUCCESS ) {
		// fallback: use hardcoded starcos specific emu
		r = starcos_esign_qes_init(p15card, aid);
		sc_log(p15card->card->ctx, "Legacy Esign/QES init returned: %d", r);
	}

	return r;
}
