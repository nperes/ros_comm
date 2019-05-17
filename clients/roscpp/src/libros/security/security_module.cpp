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

static int errorHandler(const char *str, size_t len, void *u)
{
	//TODO (nmf) work this out
	(void) len;
	(void) u;
	ROS_ERROR("%s", str);
	return 0;
}

namespace ros {

SecurityModule::SecurityModule() :
		    is_initialized(0),
		    dh_keys_(nullptr),
		    dh_secret_(nullptr),
		    dh_secret_size_(0),
		    hmac_key_(nullptr),
		    hmac_key_size_(0),
		    encryption_key_(nullptr),
		    encryption_key_size_(0),
		    dh_public_peer_key_(nullptr)
{
	if (1 == RAND_status())
		RAND_poll();
}

SecurityModule::~SecurityModule()
{
	//TODO(nmf) free() stuff
}

bool SecurityModule::initialize(boost::shared_array<uint8_t> &dh_public_key,
    size_t &dh_public_key_len, PeerKeyRetrievedFunc &peerKeyRetrievedCallback)
{

	ROS_ASSERT(!dh_keys_);
	ROS_ASSERT(!dh_public_peer_key_);

	if (!dhInitialize())
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	ROS_ASSERT(dh_keys_);

	if (!dhSerialize(dh_keys_, dh_public_key, dh_public_key_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	ROS_ASSERT(dh_keys_);

	peerKeyRetrievedCallback = boost::bind(&SecurityModule::onPeerKeyReceived, this,
	    _1, _2);

	return true;
}

bool SecurityModule::initialize(boost::shared_array<uint8_t> &dh_public_key,
    size_t &dh_public_key_len, boost::shared_array<uint8_t> dh_peer_key,
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

	if (!dhSetPeerKey()
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
	    || !dhExtractParams(dh_params, dh_keys_))
	{
		EVP_PKEY_free(dh_params); //ok to call with null
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
		return false;

	dh_public_peer_key_ = peer_key;

	EVP_PKEY *peer_derived_params = EVP_PKEY_new();
	if (!peer_derived_params
	    || (1 != EVP_PKEY_set1_DH(peer_derived_params, EVP_PKEY_get1_DH(peer_key)))
	    //TODO(nmf) refactoring
	    //|| !generateDhFromParams(peer_derived_params))
	    || !dhExtractParams(peer_derived_params, dh_keys_))
	{
		EVP_PKEY_free(dh_public_peer_key_);
		EVP_PKEY_free(peer_derived_params);
		return false;
	}

	EVP_PKEY_free(peer_derived_params);
	return true;
}


// TODO(nmf) to static
bool SecurityModule::dhSerialize(EVP_PKEY *dh_key,
    boost::shared_array<uint8_t> &dh_key_ser, size_t &dh_key_ser_size)
{
	ROS_ASSERT(dh_key);

	uint32_t aux_size = 0;
	if (0 >= (aux_size = i2d_PUBKEY(dh_key, NULL)))
		return false;

	dh_key_ser = boost::shared_array<uint8_t>(new uint8_t[aux_size]);
	// note: i2d_ moves the pointer to the end of the data
	uint8_t *aux = dh_key_ser.get();

	if (0 >= (aux_size = i2d_PUBKEY(dh_key, &aux)))
		return false;

	dh_key_ser_size = aux_size;

	return true;
}


// TODO (nmf) validate DH params
bool SecurityModule::onPeerKeyReceived(boost::shared_array<uint8_t> peer_key,
    size_t peer_key_len)
{
	ROS_ASSERT(!is_initialized);
	ROS_ASSERT(dh_keys_);

	const unsigned char *aux_buff_ptr = peer_key.get();
	EVP_PKEY *peer_key_ptr = nullptr;
	if (!(peer_key_ptr = d2i_PUBKEY(NULL, &aux_buff_ptr, peer_key_len)))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	dh_public_peer_key_ = peer_key_ptr;

	if (!dhSetPeerKey())
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	ROS_ASSERT(is_initialized);

	return true;
}


// TODO(nmf) to static
bool SecurityModule::dhExtractParams(EVP_PKEY *dh_params,
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

bool SecurityModule::dhSetPeerKey()
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

	dh_secret_ = new uint8_t[shared_secret_len];
	memcpy(dh_secret_, shared_secret, shared_secret_len);
	OPENSSL_free(shared_secret);
	dh_secret_size_ = shared_secret_len;

	if (!deriveSha256HmacKey() || !deriveAes256EncryptionKey())
		return false;

	is_initialized = true;

	return true;
}

bool SecurityModule::deriveSha256HmacKey()
{
	ROS_ASSERT(dh_secret_);
	ROS_ASSERT(!hmac_key_);

	hmac_key_size_ = EVP_MD_size(EVP_sha256());
	hmac_key_ = new uint8_t[hmac_key_size_];

	//TODO(nmf) currently dummy values -> set proper (preferably not hard coded)
	uint8_t *hmac_salt = (uint8_t*) "hmac_salt";
	size_t hmac_salt_size = strlen((char*) hmac_salt);
	uint8_t *hmac_info = (uint8_t*) "hmac_info";
	size_t hmac_info_size = strlen((char*) hmac_info);

	if (!hkdfDeriveKey(hmac_salt, hmac_salt_size, hmac_info, hmac_info_size,
	    hmac_key_, hmac_key_size_))
	{
		hmac_key_ = nullptr;
		return false;
	}

	ROS_ASSERT(hmac_key_);

	return true;
}

bool SecurityModule::deriveAes256EncryptionKey()
{
	ROS_ASSERT(dh_secret_);
	ROS_ASSERT(!encryption_key_);

	encryption_key_size_ = EVP_CIPHER_key_length(EVP_aes_256_cbc());
	encryption_key_ = new uint8_t[encryption_key_size_];

	//TODO(nmf) currently dummy values -> set proper (preferably not hard coded)
	uint8_t *encryption_salt = (uint8_t*) "encryption_salt";
	size_t encryption_salt_size = strlen((char*) encryption_salt);
	uint8_t *encryption_info = (uint8_t*) "encryption_info";
	size_t encryption_info_size = strlen((char*) encryption_info);

	if (!hkdfDeriveKey(encryption_salt, encryption_salt_size, encryption_info,
	    encryption_info_size, encryption_key_, encryption_key_size_))
	{
		encryption_key_ = nullptr;
		return false;
	}

	ROS_ASSERT(encryption_key_);

	return true;
}




bool SecurityModule::hmacSha256Generate(const uint8_t *data, size_t data_size,
    uint8_t *md_value, uint32_t &md_len) {

	HMAC(EVP_sha256(), hmac_key_, hmac_key_size_, data, data_size, md_value,
	    &md_len);

	//TODO(nmf) review this assert
	ROS_ASSERT(md_len == (uint32_t )EVP_MD_size(EVP_sha256()));

	return true;
}

bool SecurityModule::secure(boost::shared_array<uint8_t> plain_data,
    uint32_t plain_data_size, uint32_t plain_data_offset,
    boost::shared_array<uint8_t> &secure_data, uint32_t &secure_data_size,
    uint32_t secure_data_offset)
{
	static uint32_t md_size = EVP_MD_size(EVP_sha256());
	static uint32_t cipher_block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
	static uint32_t iv_size = cipher_block_size;

	// secure data format: [ secure_data_offset | hmac | iv | cyphertext ]
	uint32_t hmac_offset = secure_data_offset;
	uint32_t iv_offset = hmac_offset + md_size;
	uint32_t ciphertext_offset = iv_offset + iv_size;
	// must account for padding
	uint32_t max_ciphertext_size = (plain_data_size / cipher_block_size)
	    * cipher_block_size
	    + cipher_block_size;

	uint32_t buffer_size = ciphertext_offset + max_ciphertext_size;
	secure_data = boost::shared_array<uint8_t>(new uint8_t[buffer_size]);

	// write iv
	if (1 != RAND_bytes(secure_data.get() + iv_offset, cipher_block_size))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	// write ciphertext
	uint32_t ciphertext_len = 0;
	if (!encrypt(plain_data.get() + plain_data_offset, plain_data_size,
	    secure_data.get() + iv_offset, secure_data.get() + ciphertext_offset,
	    ciphertext_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	// write hmac(ciphertext)
	uint32_t md_len = 0;
	if (!hmacSha256Generate(secure_data.get() + ciphertext_offset, ciphertext_len,
	    secure_data.get() + hmac_offset, md_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	secure_data_size = md_size + iv_size + ciphertext_len;

	return true;
}


bool SecurityModule::retrieve(boost::shared_array<uint8_t> secure_data,
    uint32_t secure_data_size, uint32_t secure_data_offset,
    boost::shared_array<uint8_t> &plain_data, uint32_t &plain_data_size,
    uint32_t plain_data_offset) {

	ROS_ASSERT(secure_data);
	ROS_ASSERT(secure_data_size > secure_data_offset);

	static uint32_t md_size = EVP_MD_size(EVP_sha256());
	static uint32_t cipher_block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
	static uint32_t iv_size = cipher_block_size;

	// secure data format: [ secure_data_offset | hmac | iv | cyphertext ]
	uint32_t hmac_offset = secure_data_offset;
	uint32_t iv_offset = hmac_offset + md_size;
	uint32_t ciphertext_offset = iv_offset + iv_size;
	uint32_t ciphertext_size = secure_data_size - iv_size - md_size;
	uint32_t max_plaintext_size = (ciphertext_size / cipher_block_size)
	    * cipher_block_size
	    + cipher_block_size;

	uint32_t buffer_size = plain_data_offset + max_plaintext_size;
	plain_data = boost::shared_array<uint8_t>(new uint8_t[buffer_size]);

	uint8_t md_val[md_size];
	uint32_t md_len = 0;

	// verify hmac(ciphertext)
	if (!hmacSha256Generate(secure_data.get() + ciphertext_offset,
	    ciphertext_size, md_val, md_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	if (0
	    != CRYPTO_memcmp(md_val, secure_data.get() + hmac_offset,
	    		md_size))
	{
		ROS_INFO("Dropping received message: failed integrity check");
		return false;
	}

	// recover plaintext
	uint32_t plain_data_len = 0;
	if (!decrypt(secure_data.get() + ciphertext_offset, ciphertext_size,
	    secure_data.get() + iv_offset, plain_data.get() + plain_data_offset,
	    plain_data_len))
	{
		ERR_print_errors_cb(errorHandler, nullptr);
		return false;
	}

	plain_data_size = plain_data_len;

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
	    || (1 != EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, dh_secret_, dh_secret_size_))
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

// TODO(nmf) look into reusing context
bool SecurityModule::encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *iv,
    uint8_t *ciphertext, uint32_t &ciphertext_len)
{
	static const EVP_CIPHER *cipher = EVP_aes_256_cbc();

	EVP_CIPHER_CTX *cipher_ctx = nullptr;
	int tmp_len = 0;
	int len = 0;

	if (!(cipher_ctx = EVP_CIPHER_CTX_new())
	    || (1
	        != EVP_EncryptInit_ex(cipher_ctx, cipher, NULL,
	            encryption_key_, iv))
	    || (1
	        != EVP_EncryptUpdate(cipher_ctx, ciphertext, &tmp_len,
	            plaintext,
	            plaintext_len)))
	{
		EVP_CIPHER_CTX_free(cipher_ctx);
		return false;
	}
	len = tmp_len;

	if (1
	    != EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &tmp_len))
	{
		EVP_CIPHER_CTX_free(cipher_ctx);
		return false;
	}

	len += tmp_len;
	ciphertext_len = len;

	/* Clean up */
	EVP_CIPHER_CTX_free(cipher_ctx);

	return true;
}

// TODO(nmf) look into reusing context
bool SecurityModule::decrypt(uint8_t *ciphertext, uint32_t ciphertext_len,
    uint8_t *iv,
    uint8_t *plaintext, uint32_t &plaintext_len)
{
	static const EVP_CIPHER *cipher = EVP_aes_256_cbc();

	EVP_CIPHER_CTX *cipher_ctx = nullptr;
	int tmp_len = 0;
	int len = 0;

	if (!(cipher_ctx = EVP_CIPHER_CTX_new())
	    || (1
	        != EVP_DecryptInit_ex(cipher_ctx, cipher, NULL,
	            encryption_key_, iv))
	    || (1
	        != EVP_DecryptUpdate(cipher_ctx, plaintext, &tmp_len, ciphertext,
	            ciphertext_len)))
	{
		EVP_CIPHER_CTX_free(cipher_ctx);
		return false;
	}

	len += tmp_len;

	if (1 != EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &tmp_len))
	{
		EVP_CIPHER_CTX_free(cipher_ctx);
		return false;
	}

	len += tmp_len;
	plaintext_len = len;

	/* Clean up */
	EVP_CIPHER_CTX_free(cipher_ctx);

	return true;
}


} //namespace ros

