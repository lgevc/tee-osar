#include <assert.h>
#include <err.h>

//#include <tee_api_defines.h>
//#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TEE resources */
struct ca_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void bsw_csm_teec_open_session(struct ca_ctx *ctx);
void bsw_csm_teec_close_session(struct ca_ctx *ctx);

TEEC_Result ta_crypt_cmd_digest_update(TEEC_Session *s,
				       TEE_OperationHandle oph,
				       const void *chunk,
				       size_t chunk_size);
TEEC_Result ta_crypt_cmd_digest_do_final(TEEC_Session *s,
					 TEE_OperationHandle oph,
					 const void *chunk,
					 size_t chunk_len, void *hash,
					 size_t *hash_len);
TEE_Result ta_crypt_cmd_set_operation_key2(TEEC_Session *s,
					   TEE_OperationHandle oph,
					   TEE_ObjectHandle obh1,
					   TEE_ObjectHandle obh2);
TEEC_Result ta_crypt_cmd_mac_init(TEEC_Session *s,
				  TEE_OperationHandle oph,
				  const void *iv, size_t iv_len);
TEEC_Result ta_crypt_cmd_mac_update(TEEC_Session *s,
				    TEE_OperationHandle oph,
				    const void *chunk, size_t chunk_size);
TEEC_Result ta_crypt_cmd_mac_final_compute(TEEC_Session *s,
					   TEE_OperationHandle oph,
					   const void *chunk,
					   size_t chunk_len,
					   void *hash,
					   size_t *hash_len);
TEEC_Result ta_crypt_cmd_cipher_init(TEEC_Session *s,
				     TEE_OperationHandle oph,
				     const void *iv, size_t iv_len);
TEEC_Result ta_crypt_cmd_cipher_update(TEEC_Session *s,
				       TEE_OperationHandle oph,
				       const void *src, size_t src_len,
				       void *dst, size_t *dst_len);
TEEC_Result ta_crypt_cmd_cipher_do_final(TEEC_Session *s,
					 TEE_OperationHandle oph,
					 const void *src,
					 size_t src_len,
					 void *dst,
					 size_t *dst_len);
TEEC_Result ta_crypt_cmd_random_number_generate(TEEC_Session *s,
						void *buf,
						size_t blen);
TEEC_Result ta_crypt_cmd_ae_init(TEEC_Session *s,
				 TEE_OperationHandle oph,
				 const void *nonce, size_t nonce_len,
				 size_t tag_len, size_t aad_len,
				 size_t payload_len);
TEEC_Result ta_crypt_cmd_ae_update_aad(TEEC_Session *s,
				       TEE_OperationHandle oph,
				       const void *aad, size_t aad_len);
TEEC_Result ta_crypt_cmd_ae_update(TEEC_Session *s,
				   TEE_OperationHandle oph,
				   const void *src,
				   size_t src_len,
				   void *dst,
				   size_t *dst_len);
TEEC_Result ta_crypt_cmd_ae_encrypt_final(TEEC_Session *s,
					  TEE_OperationHandle oph,
					  const void *src,
					  size_t src_len, void *dst,
					  size_t *dst_len, void *tag,
					  size_t *tag_len);
TEEC_Result ta_crypt_cmd_ae_decrypt_final(TEEC_Session *s,
					  TEE_OperationHandle oph,
					  const void *src, size_t src_len,
					  void *dst, size_t *dst_len,
					  const void *tag, size_t tag_len);
TEEC_Result ta_crypt_cmd_asymmetric_operate(TEEC_Session *s,
					    TEE_OperationHandle oph,
					    uint32_t cmd,
					    const TEE_Attribute *params,
					    uint32_t paramCount,
					    const void *src,
					    size_t src_len,
					    void *dst,
					    size_t *dst_len);
TEEC_Result ta_crypt_cmd_asymmetric_encrypt(TEEC_Session *s,
					    TEE_OperationHandle oph,
					    const TEE_Attribute *params,
					    uint32_t paramCount,
					    const void *src,
					    size_t src_len,
					    void *dst,
					    size_t *dst_len);
TEEC_Result ta_crypt_cmd_asymmetric_decrypt(TEEC_Session *s,
					    TEE_OperationHandle oph,
					    const TEE_Attribute *params,
					    uint32_t paramCount,
					    const void *src,
					    size_t src_len,
					    void *dst,
					    size_t *dst_len);
TEEC_Result ta_crypt_cmd_asymmetric_sign(TEEC_Session *s,
					 TEE_OperationHandle oph,
					 const TEE_Attribute *params,
					 uint32_t paramCount,
					 const void *digest,
					 size_t digest_len,
					 void *signature,
					 size_t *signature_len);
TEEC_Result ta_crypt_cmd_asymmetric_verify(TEEC_Session *s,
					   TEE_OperationHandle oph,
					   const TEE_Attribute *params,
					   uint32_t paramCount,
					   const void *digest,
					   size_t digest_len,
					   const void *signature,
					   size_t signature_len);
TEEC_Result ta_crypt_cmd_get_object_value_attribute(TEEC_Session *s,
						    TEE_ObjectHandle obh,
						    uint32_t attr_id,
						    uint32_t *valuea,
						    uint32_t *valueb);
TEEC_Result ta_crypt_cmd_generate_key(TEEC_Session *s,
				      TEE_ObjectHandle obh,
				      uint32_t key_size,
				      const TEE_Attribute *params,
				      uint32_t paramCount);
