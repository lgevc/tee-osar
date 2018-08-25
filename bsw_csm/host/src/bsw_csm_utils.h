#include <stdio.h>
//#include <string.h>
#include <malloc.h>

#include <tee_api_types.h>

#define TEEC_OPERATION_INITIALIZER { 0 }

TEEC_Result ta_crypt_cmd_allocate_operation(TEEC_Session *s,
					    TEE_OperationHandle *oph,
					    uint32_t algo,
					    uint32_t mode,
					    uint32_t max_key_size);

TEEC_Result ta_crypt_cmd_allocate_transient_object(TEEC_Session *s,
						   TEE_ObjectType obj_type, uint32_t max_obj_size,
						   TEE_ObjectHandle *obh);

TEEC_Result ta_crypt_cmd_populate_transient_object(TEEC_Session *s,
						   TEE_ObjectHandle obh,
						   const TEE_Attribute *attrs,
						   uint32_t attr_count);

TEE_Result ta_crypt_cmd_set_operation_key(TEEC_Session *s,
					  TEE_OperationHandle oph,
					  TEE_ObjectHandle key);

TEEC_Result ta_crypt_cmd_free_transient_object(TEEC_Session *s,
					       TEE_ObjectHandle obh);

TEEC_Result ta_crypt_cmd_get_object_buffer_attribute(TEEC_Session *s,
						     TEE_ObjectHandle obh,
						     uint32_t attr_id,
						     void *buf,
						     size_t *blen);

TEEC_Result ta_crypt_cmd_free_operation(TEEC_Session *s,
					TEE_OperationHandle oph);

void tee_add_attr(size_t *attr_count, TEE_Attribute *attrs,
		  uint32_t attr_id, const void *buf, size_t len);
void tee_add_attr_value(size_t *attr_count, TEE_Attribute *attrs,
			uint32_t attr_id, uint32_t value_a, uint32_t value_b);

TEE_Result tee_pack_attrs(const TEE_Attribute *attrs, uint32_t attr_count,
			  uint8_t **buf, size_t *blen);
