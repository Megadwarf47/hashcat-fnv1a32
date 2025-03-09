/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

 // Define constants for FNV-1a 32-bit
static const u32 FNV_OFFSET_BASIS = 0x811C9DC5; // FNV offset basis for 32-bit
static const u32 FNV_32_PRIME = 0x01000193;    // FNV prime for 32-bit

static const u32   ATTACK_EXEC = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0 = 0;
static const u32   DGST_SIZE = DGST_SIZE_4_4; // 32-bit hash means 4 bytes
static const u32   HASH_CATEGORY = HASH_CATEGORY_HACKS;
static const char* HASH_NAME = "FNV-1a 32-bit";
static const u64   KERN_TYPE = 88888;
static const u32   OPTI_TYPE = OPTI_TYPE_ZERO_BYTE
| OPTI_TYPE_NOT_ITERATED
| OPTI_TYPE_NOT_SALTED
| OPTI_TYPE_USES_BITS_64;
static const u64   OPTS_TYPE = OPTS_TYPE_PT_GENERATE_LE
| OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE = SALT_TYPE_NONE;
static const char* ST_PASS = "klifaa.sys";
static const char* ST_HASH = "14605870802367138151";

u32         module_attack_exec(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return ATTACK_EXEC; }
u32         module_dgst_pos0(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return DGST_POS0; }
u32         module_dgst_size(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return DGST_SIZE; }
u32         module_hash_category(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return HASH_CATEGORY; }
const char* module_hash_name(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return HASH_NAME; }
u64         module_kern_type(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return KERN_TYPE; }
u32         module_opti_type(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return OPTI_TYPE; }
u64         module_opts_type(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return OPTS_TYPE; }
u32         module_salt_type(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return SALT_TYPE; }
const char* module_st_hash(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return ST_HASH; }
const char* module_st_pass(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra) { return ST_PASS; }

bool module_unstable_warning(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra, MAYBE_UNUSED const hc_device_param_t* device_param)
{
  return false; // No warning for FNV-1a 32-bit hashing
}

char* module_jit_build_options(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const user_options_t* user_options, MAYBE_UNUSED const user_options_extra_t* user_options_extra, MAYBE_UNUSED const hashes_t* hashes, MAYBE_UNUSED const hc_device_param_t* device_param)
{
  return NULL; // No special JIT build options needed
}

int module_hash_decode(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED void* digest_buf, MAYBE_UNUSED salt_t* salt, MAYBE_UNUSED void* esalt_buf, MAYBE_UNUSED void* hook_salt_buf, MAYBE_UNUSED hashinfo_t* hash_info, const char* line_buf, MAYBE_UNUSED const int line_len)
{
  u32* digest = (u32*)digest_buf; // 32-bit digest

  token_t token;
  token.token_cnt = 1;
  token.len_min[0] = 8;  // Minimum length for 32-bit hash (8 hex digits)
  token.len_max[0] = 8;  // Maximum length for 32-bit hash
  token.attr[0] = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer((const u8*)line_buf, line_len, &token);
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const char* hash_pos = (char*)token.buf[0];

  // Convert the hex hash string to an unsigned integer (u32)
  u32 n = (u32)strtol(hash_pos, NULL, 16);

  // FNV-1a 32-bit reversal
  u32 val = 0x811C9DC5; // FNV-1a offset basis for 32-bit
  n ^= val;

  digest[0] = n;

  return (PARSER_OK);
}

int module_hash_encode(MAYBE_UNUSED const hashconfig_t* hashconfig, MAYBE_UNUSED const void* digest_buf, MAYBE_UNUSED const salt_t* salt, MAYBE_UNUSED const void* esalt_buf, MAYBE_UNUSED const void* hook_salt_buf, MAYBE_UNUSED const hashinfo_t* hash_info, char* line_buf, MAYBE_UNUSED const int line_size)
{
  const u32* digest = (const u32*)digest_buf; // 32-bit digest

  // Convert the 32-bit digest to a string and store in line_buf
  return snprintf(line_buf, line_size, "%08x", digest[0]); // 8 hex digits for 32-bit hash
}

void module_init(module_ctx_t* module_ctx)
{
  module_ctx->module_context_size = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec = module_attack_exec;
  module_ctx->module_benchmark_esalt = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0 = module_dgst_pos0;
  module_ctx->module_dgst_size = module_dgst_size;
  module_ctx->module_dictstat_disable = MODULE_DEFAULT;
  module_ctx->module_esalt_size = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash = MODULE_DEFAULT;
  module_ctx->module_hash_decode = module_hash_decode;
  module_ctx->module_hash_encode_status = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_encode = module_hash_encode;
  module_ctx->module_hash_init_selftest = MODULE_DEFAULT;
  module_ctx->module_hash_mode = MODULE_DEFAULT;
  module_ctx->module_hash_category = module_hash_category;
  module_ctx->module_hash_name = module_hash_name;
  module_ctx->module_hashes_count_min = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term = MODULE_DEFAULT;
  module_ctx->module_hook12 = MODULE_DEFAULT;
  module_ctx->module_hook23 = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size = MODULE_DEFAULT;
  module_ctx->module_hook_size = MODULE_DEFAULT;
  module_ctx->module_jit_build_options = module_jit_build_options;
  module_ctx->module_jit_cache_disable = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min = MODULE_DEFAULT;
  module_ctx->module_kern_type = module_kern_type;
  module_ctx->module_kern_type_dynamic = MODULE_DEFAULT;
  module_ctx->module_opti_type = module_opti_type;
  module_ctx->module_opts_type = module_opts_type;
  module_ctx->module_outfile_check_disable = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check = MODULE_DEFAULT;
  module_ctx->module_potfile_disable = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes = MODULE_DEFAULT;
  module_ctx->module_pwdump_column = MODULE_DEFAULT;
  module_ctx->module_pw_max = MODULE_DEFAULT;
  module_ctx->module_pw_min = MODULE_DEFAULT;
  module_ctx->module_salt_max = MODULE_DEFAULT;
  module_ctx
