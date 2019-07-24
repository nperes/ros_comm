/*
 * security_module.cpp
 *
 *      Author: nmf
 */
#include "ros/security/security_module.h"
#include <openssl/err.h>
#include "ros/console.h"
#include <ros/assert.h>

#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <boost/bind.hpp>

//TODO(nmf) temporary
static int errorHandler(const char *str, size_t len, void *u)
{
	(void) len;
	(void) u;
	ROS_ERROR("%s", str);
	return 0;
}

namespace ros {

// TODO(nmf) add proper error handling throughout
SecurityModule::SecurityModule(int flags) :
		    dh_keys_(nullptr),
		    dh_secret_(nullptr),
		    dh_secret_len_(0),
		    md_key_(nullptr),
		    md_pkey_(nullptr),
		    md_key_size_(0),
		    cipher_key_(nullptr),
		    dh_public_peer_key_(nullptr),
		    evp_cipher_(nullptr),
		    cipher_ctx_(nullptr),
		    md_algorithm_(nullptr),
		    md_ctx_(nullptr),
		    md_len_(0)
{
	flags_ = flags;
	if (1 == RAND_status())
		RAND_poll();
}

SecurityModule::~SecurityModule()
{
	EVP_PKEY_free(dh_keys_);
	delete[] dh_secret_;
	delete[] md_key_;
	delete[] cipher_key_;
	EVP_PKEY_free(dh_public_peer_key_);
	EVP_MD_CTX_free(md_ctx_);
	EVP_CIPHER_CTX_free(cipher_ctx_);
}

bool SecurityModule::initialize(boost::shared_array<uint8_t> &dh_public_key,
    size_t &dh_public_key_len, PeerKeyRetrievedFunc &peerKeyRetrievedCallback)
{
	ROS_ASSERT(!dh_keys_);

	if (!dhInitialize()
	    || !dhSerialize(dh_keys_, dh_public_key, dh_public_key_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	peerKeyRetrievedCallback = boost::bind(&SecurityModule::onDhPeerKeyAvailable, this,
	    _1, _2);

	return true;
}

bool SecurityModule::initialize(boost::shared_array<uint8_t> &dh_public_key,
    size_t &dh_public_key_len, const boost::shared_array<uint8_t>& dh_peer_key,
    size_t dh_peer_key_len)
{

	ROS_ASSERT(!dh_keys_);

	if (!dhInitialize(dh_peer_key.get(), dh_peer_key_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	ROS_ASSERT(dh_keys_);
	ROS_ASSERT(dh_public_peer_key_);

	if (!onDhPeerKey()
	    || !dhSerialize(dh_keys_, dh_public_key, dh_public_key_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	return true;
}

bool SecurityModule::dhInitialize()
{
	EVP_PKEY *dh_params = nullptr;
	if (!(dh_params = EVP_PKEY_new())
	    || (1 != EVP_PKEY_set1_DH(dh_params, DH_get_2048_256()))
	    || !dhGenerateFromParams(dh_params, dh_keys_))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		EVP_PKEY_free(dh_params);
		return false;
	}

	EVP_PKEY_free(dh_params);

	return true;
}


bool SecurityModule::dhInitialize(const uint8_t *dh_peer_key,
    uint32_t dh_peer_key_len)
{
	const uint8_t *dh_peer_key_proxy = dh_peer_key;
	EVP_PKEY *peer_key = nullptr;

	if (!(peer_key = d2i_PUBKEY(nullptr, &dh_peer_key_proxy, dh_peer_key_len)))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	dh_public_peer_key_ = peer_key;

	EVP_PKEY *peer_derived_params = EVP_PKEY_new();
	if (!peer_derived_params
	    || (1 != EVP_PKEY_set1_DH(peer_derived_params, EVP_PKEY_get1_DH(peer_key)))
	    || !dhGenerateFromParams(peer_derived_params, dh_keys_))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		EVP_PKEY_free(dh_public_peer_key_);
		EVP_PKEY_free(peer_derived_params);
		return false;
	}

	EVP_PKEY_free(peer_derived_params);

	return true;
}

bool SecurityModule::dhParseKey(const uint8_t *dh_peer_key,
    size_t dh_peer_key_size)
{
	const uint8_t *dh_peer_key_proxy = dh_peer_key;
	EVP_PKEY *peer_key = nullptr;

	if (!(peer_key = d2i_PUBKEY(nullptr, &dh_peer_key_proxy, dh_peer_key_size)))
	{
		return false;
	}

	return true;
}

bool SecurityModule::setCryptoOps()
{
	setHmacs(flags_ & HMACS);
	setEncryption(flags_ & ENCRYPTION);

	return (md_algorithm_ && evp_cipher_);
}

SecurityModule& SecurityModule::setHmacs(bool enable)
{
	const EVP_MD *md_algo = nullptr;

	if (enable)
	{
		flags_ |= HMACS;
		md_algo = EVP_sha256();
	} else
	{
		flags_ &= ~HMACS;
		md_algo = EVP_md_null();
	}

	if (!md_algo)
	{
		ERR_print_errors_cb(errorHandler, nullptr);
	}
	else
	{
		md_algorithm_ = md_algo;
		md_len_ = EVP_MD_size(md_algorithm_);
		md_key_size_ = EVP_MD_block_size(md_algorithm_);
	}

	return *this;
}

SecurityModule& SecurityModule::setEncryption(bool enable)
{
	const EVP_CIPHER *evp_cipher_aux = nullptr;

	if (enable)
	{
		flags_ |= ENCRYPTION;
		evp_cipher_aux = EVP_aes_256_cbc();
	} else
	{
		flags_ &= ~ENCRYPTION;
		evp_cipher_aux = EVP_enc_null();
	}

	if (!evp_cipher_aux)
	{
		ERR_print_errors_cb(errorHandler, nullptr);
	}
	else
	{
		evp_cipher_ = evp_cipher_aux;
	}

	return *this;
}


bool SecurityModule::dhSerialize(EVP_PKEY *dh_key,
    boost::shared_array<uint8_t> &dh_key_ser, size_t &dh_key_ser_size)
{
	ROS_ASSERT(dh_key);

	uint32_t out_len = 0;
	if (0 >= (out_len = i2d_PUBKEY(dh_key, NULL)))
	{
		return false;
	}

	dh_key_ser = boost::shared_array<uint8_t>(new uint8_t[out_len]);
	// note: i2d_ moves the pointer to the end of the data
	uint8_t *aux = dh_key_ser.get();

	if (0 >= (out_len = i2d_PUBKEY(dh_key, &aux)))
	{
		return false;
	}

	dh_key_ser_size = out_len;

	return true;
}


// TODO (nmf) handle differently + validate DH params
bool SecurityModule::onDhPeerKeyAvailable(boost::shared_array<uint8_t> peer_key,
    size_t peer_key_len)
{
	ROS_ASSERT(dh_keys_);

	const unsigned char *aux_buff_ptr = peer_key.get();
	EVP_PKEY *peer_key_ptr = nullptr;
	if (!(peer_key_ptr = d2i_PUBKEY(NULL, &aux_buff_ptr, peer_key_len)))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	dh_public_peer_key_ = peer_key_ptr;

	if (!onDhPeerKey())
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	return true;
}


bool SecurityModule::dhGenerateFromParams(EVP_PKEY *dh_params,
    EVP_PKEY* &dh_keys)
{
	EVP_PKEY_CTX *pk_ctx = nullptr;

	if (!(pk_ctx = EVP_PKEY_CTX_new(dh_params, nullptr))
	    || (1 != EVP_PKEY_keygen_init(pk_ctx))
	    || (1 != EVP_PKEY_keygen(pk_ctx, &dh_keys)))
	{
		EVP_PKEY_CTX_free(pk_ctx); //ok to call with null
		EVP_PKEY_free(dh_keys); //ok to call with null
		return false;
	}

	EVP_PKEY_CTX_free(pk_ctx); //ok to call with null
	return true;
}

bool SecurityModule::onDhPeerKey()
{
	ROS_ASSERT(dh_keys_);
	ROS_ASSERT(dh_public_peer_key_);


	EVP_PKEY_CTX *pkey_ctx = nullptr;
	size_t shared_secret_len = 0;
	uint8_t *shared_secret = nullptr;

	if (!(pkey_ctx = EVP_PKEY_CTX_new(dh_keys_, NULL))
	    || 1 != EVP_PKEY_derive_init(pkey_ctx)
	    || 1 != EVP_PKEY_derive_set_peer(pkey_ctx, dh_public_peer_key_)
	    || 1 != EVP_PKEY_derive(pkey_ctx, NULL, &shared_secret_len)
	    || !(shared_secret = (uint8_t*) OPENSSL_malloc(shared_secret_len))
	    || 1 != EVP_PKEY_derive(pkey_ctx, shared_secret, &shared_secret_len))
	{
		EVP_PKEY_CTX_free(pkey_ctx);
		return false;
	}

	dh_secret_len_ = shared_secret_len;
	dh_secret_ = new uint8_t[shared_secret_len];
	memcpy(dh_secret_, shared_secret, shared_secret_len);

	OPENSSL_clear_free(shared_secret, shared_secret_len);

	if (!setCryptoOps() || !deriveSha256HmacKey() || !deriveAes256EncryptionKey())
		return false;

	if (!(md_pkey_ = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, md_key_,
	    md_key_size_)))
		return false;

	if (!(md_ctx_ = EVP_MD_CTX_new()) || !(cipher_ctx_ = EVP_CIPHER_CTX_new()))
	{
		EVP_MD_CTX_free(md_ctx_);
		EVP_CIPHER_CTX_free(cipher_ctx_);
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	return true;
}


bool SecurityModule::secure(const uint8_t *in_data, uint32_t in_len,
    boost::shared_array<uint8_t> &out_buffer, uint32_t &out_written,
    uint32_t out_offset)
{

	ROS_ASSERT(md_algorithm_);
	ROS_ASSERT(evp_cipher_);
	ROS_ASSERT(in_data);
	ROS_ASSERT(in_len > 0);

	if (!aes256Encrypt(in_data, in_len, out_buffer, out_written,
	    out_offset + md_len_))
	{
		return false;
	}

	const uint8_t *in_hmac_data = out_buffer.get() + out_offset + md_len_;
	uint32_t in_hmac_data_len = out_written;
	if (!mdGenerate(in_hmac_data, in_hmac_data_len, out_buffer, out_offset))
	{
		return false;
	}

	out_written += md_len_;

	return true;
}

bool SecurityModule::retrieve(const uint8_t *in_data, uint32_t in_len,
    boost::shared_array<uint8_t> &out_buffer, uint32_t &out_written,
    uint32_t out_offset)
{
	ROS_ASSERT(md_algorithm_);
	ROS_ASSERT(evp_cipher_);
	ROS_ASSERT(in_data);
	ROS_ASSERT(in_len > 0);

	if (!mdValidate(in_data + md_len_, in_len - md_len_, in_data))
	{
		return false;
	}

	if (!aes256Decrypt(in_data + md_len_, in_len - md_len_, out_buffer,
	    out_written, out_offset))
	{
		return false;
	}

	return true;
}


/******************************************************************************
 * (Private) Secure/Retrieve Methods
 *****************************************************************************/

bool SecurityModule::deriveSha256HmacKey()
{
	ROS_ASSERT(dh_secret_);
	ROS_ASSERT(!md_key_);
	ROS_ASSERT(md_algorithm_);

	md_key_size_ = EVP_MD_size(EVP_sha256());
	md_key_ = new uint8_t[md_key_size_];

	//TODO(nmf) currently dummy values -> set proper (preferably not hard coded)
	uint8_t *hmac_salt = (uint8_t*) "hmac_salt";
	size_t hmac_salt_size = strlen((char*) hmac_salt);
	uint8_t *hmac_info = (uint8_t*) "hmac_info";
	size_t hmac_info_size = strlen((char*) hmac_info);

	if (!hkdfDeriveKey(hmac_salt, hmac_salt_size, hmac_info, hmac_info_size,
	    md_key_, md_key_size_))
	{
		md_key_ = nullptr;
		return false;
	}

	ROS_ASSERT(md_key_);

	return true;
}

bool SecurityModule::deriveAes256EncryptionKey()
{
	ROS_ASSERT(dh_secret_);
	ROS_ASSERT(!cipher_key_);

	size_t cipher_key_size = EVP_CIPHER_key_length(EVP_aes_256_cbc());
	cipher_key_ = new uint8_t[cipher_key_size];

	//TODO(nmf) currently dummy values -> set proper (preferably not hard coded)
	uint8_t *encryption_salt = (uint8_t*) "encryption_salt";
	size_t encryption_salt_size = strlen((char*) encryption_salt);
	uint8_t *encryption_info = (uint8_t*) "encryption_info";
	size_t encryption_info_size = strlen((char*) encryption_info);

	if (!hkdfDeriveKey(encryption_salt, encryption_salt_size, encryption_info,
	    encryption_info_size, cipher_key_, cipher_key_size))
	{
		cipher_key_ = nullptr;
		return false;
	}


	ROS_ASSERT(cipher_key_);

	return true;
}

bool SecurityModule::hkdfDeriveKey(const uint8_t *salt, size_t salt_size,
    const uint8_t *info, size_t info_size, uint8_t *key, size_t key_size)
{
	ROS_ASSERT(dh_secret_);

	EVP_PKEY_CTX *hkdf_ctx = nullptr;
	uint8_t *derived_key = new uint8_t[EVP_MAX_KEY_LENGTH];
	size_t derived_key_size = key_size;

	if (!(hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL))
	    || (1 != EVP_PKEY_derive_init(hkdf_ctx))
	    || (1 != EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()))
	    || (1 != EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, dh_secret_, dh_secret_len_))
	    || (1 != EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, salt, salt_size))
	    || (1 != EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, info, info_size))
	    || (1 != EVP_PKEY_derive(hkdf_ctx, derived_key, &derived_key_size)))
	{
		EVP_PKEY_CTX_free(hkdf_ctx);
		return false;
	}

	ROS_ASSERT(derived_key_size == key_size);

	EVP_PKEY_CTX_free(hkdf_ctx);

	memcpy(key, derived_key, key_size);

	return true;
}

bool SecurityModule::mdGenerate(const uint8_t *msg, uint32_t msg_len,
    boost::shared_array<uint8_t>& md, uint32_t md_offset)
{
	if (!md)
		md = boost::shared_array<uint8_t>(new uint8_t[md_offset + md_len_]);

	size_t md_len;

	if (1 != EVP_DigestInit_ex(md_ctx_, md_algorithm_, NULL)
	    || 1
	        != EVP_DigestSignInit(md_ctx_, nullptr, md_algorithm_, nullptr,
	            md_pkey_) || 1 != EVP_DigestSignUpdate(md_ctx_, msg, msg_len)
	    || 1 != EVP_DigestSignFinal(md_ctx_, md.get() + md_offset, &md_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	ROS_ASSERT(md_len == md_len_);

	return true;
}

bool SecurityModule::mdValidate(const uint8_t *msg, uint32_t msg_len,
    const uint8_t* md)
{
	boost::shared_array<uint8_t> md_tmp = boost::shared_array<uint8_t>(
	    new uint8_t[md_len_]);

	if (!mdGenerate(msg, msg_len, md_tmp))
	{
		return false;
	}

	if (0 != CRYPTO_memcmp(md_tmp.get(), md, md_len_))
	{
		ROS_DEBUG_NAMED("superdebug", "HMAC Verify: failed integrity check");
		return false;
	}

	return true;
}


bool SecurityModule::aes256Encrypt(const uint8_t *plaintext,
    uint32_t plaintext_size, boost::shared_array<uint8_t> &buffer,
    uint32_t &size, uint32_t offset)
{
	uint32_t cipher_block_size = EVP_CIPHER_block_size(evp_cipher_);
	uint32_t iv_size = EVP_CIPHER_iv_length(evp_cipher_);

	if (!buffer)
	{
		// take padding into account
		uint32_t max_ciphertext_size = (plaintext_size / cipher_block_size)
		    * cipher_block_size + cipher_block_size;
		uint32_t buffer_size = offset + iv_size + max_ciphertext_size;
		buffer = boost::shared_array<uint8_t>(new uint8_t[buffer_size]);
	}

	uint8_t *iv = buffer.get() + offset;
	uint8_t *ciphertext = iv + iv_size;

	// new random IV for this encryption
	if (1 != RAND_bytes(iv, iv_size))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	uint32_t ciphertext_len = 0;
	if (!evp_cipher(plaintext, plaintext_size, ciphertext, ciphertext_len, iv,
	    true))
	{
		return false;
	}

	size = iv_size + ciphertext_len;

	return true;
}

bool SecurityModule::aes256Decrypt(const uint8_t *ciphered_data,
    uint32_t ciphered_data_len, boost::shared_array<uint8_t> &buffer,
    uint32_t &size, uint32_t offset)
{
	uint32_t cipher_block_size = EVP_CIPHER_block_size(evp_cipher_);
	uint32_t iv_size = EVP_CIPHER_iv_length(evp_cipher_);

	const uint8_t *iv = ciphered_data;
	const uint8_t *ciphertext = iv + iv_size;

	uint32_t ciphertext_size = ciphered_data_len - iv_size;

	if (!buffer)
	{
		// account for padding
		uint32_t max_plaintext_size = (ciphertext_size / cipher_block_size)
		    * cipher_block_size + cipher_block_size;
		uint32_t buffer_size = offset + max_plaintext_size;
		buffer = boost::shared_array<uint8_t>(new uint8_t[buffer_size]);
	}

	uint32_t decrypt_len = 0;
	if (!evp_cipher(ciphertext, ciphertext_size, buffer.get() + offset,
	    decrypt_len, iv, false))
	{
		return false;
	}

	size = decrypt_len;

	return true;
}

bool SecurityModule::evp_cipher(const uint8_t *input, int input_len,
    uint8_t *output, uint32_t &output_len, const uint8_t *iv, bool encrypt)
{

	int key_length = EVP_CIPHER_key_length(evp_cipher_);
	int iv_length = EVP_CIPHER_iv_length(evp_cipher_);
	int do_encrypt = encrypt ? 1 : 0;

	if (1
	    != (EVP_CipherInit_ex(cipher_ctx_, evp_cipher_, NULL, NULL, NULL,
	        do_encrypt)))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	ROS_ASSERT(EVP_CIPHER_CTX_key_length(cipher_ctx_) == key_length);
	ROS_ASSERT(EVP_CIPHER_CTX_iv_length(cipher_ctx_) == iv_length);

	int tmp_len = 0, current_len = 0;

	if ((1
	    != EVP_CipherInit_ex(cipher_ctx_, evp_cipher_, NULL, cipher_key_, iv,
	            do_encrypt))
	|| (1 != EVP_CipherUpdate(cipher_ctx_, output, &tmp_len, input, input_len)))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	current_len = tmp_len;

	if (1 != EVP_CipherFinal_ex(cipher_ctx_, output + current_len, &tmp_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	current_len += tmp_len;
	output_len = current_len;

	return true;
}

} //namespace ros

