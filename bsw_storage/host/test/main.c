#include <stdio.h>
#include <err.h>

#include <ca_bsw_storage.h>

static uint8_t file_00[] = {
	0x00, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
};

static uint8_t file_01[] = {
	0x01, 0x00
};

static uint8_t file_02[] = {
	0x02, 0x11, 0x02
};

static uint8_t data_00[] = {
	0x00, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0x00, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0x00, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0x00, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x00
};

static uint8_t data_01[] = {
	0x01, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0x01, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0x01, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0x01, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x01
};

static TEEC_Result test_bsw_storage_fs_create(struct ca_ctx *ctx, uint32_t storage_id)
{
	uint32_t obj;
	TEEC_Result res;

	res = fs_create(&ctx->sess, file_00, sizeof(file_00),
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			sizeof(data_00), &obj, storage_id);
	if(!res)
		return res;

	res = fs_unlink(&ctx->sess, obj);
	if(!res)
		return res;

	return res;
}

static TEEC_Result test_bsw_storage_fs_open(struct ca_ctx *ctx, uint32_t storage_id)
{
	uint32_t obj;
	TEEC_Result res;

	res = fs_create(&ctx->sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE, 0, data_00,
			sizeof(data_00), &obj, storage_id);
	if(!res)
		return res;

	res = fs_open(&ctx->sess, file_01, sizeof(file_01),
		      TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id);
	if(!res)
		return res;

	res = fs_close(&ctx->sess, obj);
	if(!res)
		return res;

	res = fs_open(&ctx->sess, file_01, sizeof(file_01),
		      TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id);
	if(!res)
		return res;

	res = fs_unlink(&ctx->sess, obj);
	if(!res)
		return res;

	return res;
}

static TEEC_Result test_bsw_storage_fs_read(struct ca_ctx *ctx, uint32_t storage_id)
{
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	TEEC_Result res;
	int i;

	res = fs_create(&ctx->sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			sizeof(data_01), &obj, storage_id);
	if(!res)
		return res;

	res = fs_close(&ctx->sess, obj);
	if(!res)
		return res;

	res = fs_open(&ctx->sess, file_02, sizeof(file_02),
		      TEE_DATA_FLAG_ACCESS_READ |
		      TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id);
	if(!res)
		return res;

	res = fs_read(&ctx->sess, obj, out, 10, &count);
	if(!res)
		return res;
	for (i = 0; i < 10; i++) printf("0x%x ", out[i]);
	printf("\n");

	res = fs_unlink(&ctx->sess, obj);
	if(!res)
		return res;

	return res;
}

static TEEC_Result test_bsw_storage_fs_write(struct ca_ctx *ctx, uint32_t storage_id)
{
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	TEEC_Result res;
	int i;

	res = fs_create(&ctx->sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			sizeof(data_01), &obj, storage_id);
	if(!res)
		return res;

	res = fs_close(&ctx->sess, obj);
	if(!res)
		return res;

	res = fs_open(&ctx->sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE, &obj, storage_id);
	if(!res)
		return res;

	res = fs_write(&ctx->sess, obj, data_00, sizeof(data_00));
	if(!res)
		return res;

	res = fs_close(&ctx->sess, obj);
	if(!res)
		return res;

	res = fs_open(&ctx->sess, file_02, sizeof(file_02),
		      TEE_DATA_FLAG_ACCESS_READ |
		      TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id);
	if(!res)
		return res;

	/* verify */
	res = fs_read(&ctx->sess, obj, out, 10, &count);
	if(!res)
		return res;
	for (i = 0; i < 10; i++) printf("0x%x ", out[i]);
	printf("\n");

	res = fs_unlink(&ctx->sess, obj);
	if(!res)
		return res;

	return res;
}

static TEEC_Result test_bsw_storage_fs_seek(struct ca_ctx *ctx, uint32_t storage_id)
{
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	TEEC_Result res;
	int i;

	res = fs_create(&ctx->sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			sizeof(data_00), &obj, storage_id);
	if(!res)
		return res;

	res = fs_seek(&ctx->sess, obj, 10, TEE_DATA_SEEK_SET);
	if(!res)
		return res;

	/* verify */
	res = fs_read(&ctx->sess, obj, out, 10, &count);
	if(!res)
		return res;
	for (i = 0; i < 10; i++) printf("0x%x ", out[i]);
	printf("\n");

	res = fs_unlink(&ctx->sess, obj);
	if(!res)
		return res;

	return res;
}

static TEEC_Result test_bsw_storage_fs_unlink(struct ca_ctx *ctx, uint32_t storage_id)
{
	uint32_t obj;
	TEEC_Result res;

	res = fs_create(&ctx->sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			sizeof(data_00), &obj, storage_id);
	if(!res)
		return res;

	res = fs_unlink(&ctx->sess, obj);
	if(!res)
		return res;

	/* check */
	res = fs_open(&ctx->sess, file_01, sizeof(file_01),
		      TEE_DATA_FLAG_ACCESS_READ, &obj, storage_id);
	printf("unlink 0x%x", res);
	if(res != TEEC_ERROR_ITEM_NOT_FOUND)
		return res;

	return res;
}

int main(int argc, char *argv[])
{
	struct ca_ctx ctx;
	TEEC_Result res;

	printf("Prepare session with the TA\n");
	bsw_storage_teec_open_session(&ctx);

	printf("Test TEE_CreatePersistentObject\n");
	res = test_bsw_storage_fs_create(&ctx, TEE_STORAGE_PRIVATE);
	if(res != TEEC_SUCCESS)
		errx(1, "fs create failed with code 0x%x", res);

	printf("Test TEE_OpenPersistentObject\n");
	res = test_bsw_storage_fs_open(&ctx, TEE_STORAGE_PRIVATE);
	if(res != TEEC_SUCCESS)
		errx(1, "fs open failed with code 0x%x", res);

	printf("Test TEE_ReadObjectData\n");
	res = test_bsw_storage_fs_read(&ctx, TEE_STORAGE_PRIVATE);
	if(res != TEEC_SUCCESS)
		errx(1, "fs read failed with code 0x%x", res);

	printf("Test TEE_WriteObjectData\n");
	res = test_bsw_storage_fs_write(&ctx, TEE_STORAGE_PRIVATE);
	if(res != TEEC_SUCCESS)
		errx(1, "fs write failed with code 0x%x", res);

	printf("Test TEE_SeekObjectData\n");
	res = test_bsw_storage_fs_seek(&ctx, TEE_STORAGE_PRIVATE);
	if(res != TEEC_SUCCESS)
		errx(1, "fs seek failed with code 0x%x", res);

	printf("Test TEE_CloseAndDeletePersistentObject\n");
	res = test_bsw_storage_fs_unlink(&ctx, TEE_STORAGE_PRIVATE);
	if(res != TEEC_SUCCESS)
		errx(1, "fs unlink failed with code 0x%x", res);

	bsw_storage_teec_close_session(&ctx);

	return 0;
}
